/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"strings"
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/intel/trusted-attestation-controller/pkg/registryserver"
	tcsapi "github.com/intel/trusted-certificate-issuer/api/v1alpha2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// QuoteAttestationReconciler reconciles a QuoteAttestation object
type QuoteAttestationReconciler struct {
	client.Client
	registry *registryserver.PluginRegistry
	scheme   *runtime.Scheme
	lock     sync.Mutex
	// pluginName holds the name of the plugin to use for
	// key provisioning/quote validation.
	// The value supposed to come from QuoteAttestation request.
	pluginName string
}

func NewQuoteAttestationReconciler(c client.Client, registry *registryserver.PluginRegistry, scheme *runtime.Scheme, pluginName string) *QuoteAttestationReconciler {
	return &QuoteAttestationReconciler{
		Client:     c,
		registry:   registry,
		scheme:     scheme,
		pluginName: pluginName,
	}
}

//+kubebuilder:rbac:groups=tcs.intel.com,resources=quoteattestations,verbs=get;list;watch
//+kubebuilder:rbac:groups=tcs.intel.com,resources=quoteattestations/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=tcs.intel.com,resources=quoteattestations/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;create;update;delete

func (r *QuoteAttestationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.Log.WithValues("req", req)
	l.Info("Reconcile")

	r.lock.Lock()
	defer r.lock.Unlock()

	qa := &tcsapi.QuoteAttestation{}
	if err := client.IgnoreNotFound(r.Client.Get(ctx, req.NamespacedName, qa)); err != nil {
		l.Info("Failed to fetch object", "req", req)
		return ctrl.Result{}, err
	}

	if !qa.ObjectMeta.DeletionTimestamp.IsZero() {
		// object being deleted, just ignore
		l.Info("Ignoring as the object is set for deletion!")
		return ctrl.Result{}, nil
	}

	copy := qa.DeepCopy()

	patchStatus := func() {
		patch := client.MergeFrom(copy)
		if err := r.Client.Status().Patch(ctx, qa, patch); err != nil {
			l.Error(err, "Failed to patch status:")
		}
	}

	cond := qa.Status.GetCondition(tcsapi.ConditionReady)
	if cond == nil {
		l.Info("First seen initiating the status.")
		qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionUnknown, tcsapi.ReasonControllerReconcile, "First seen")
		patchStatus()
		return ctrl.Result{}, nil
	}

	if cond.Status != v1.ConditionUnknown {
		l.Info("Ignoring as it is already in ready.", "status", cond.Status, "message", cond.Message)
		return ctrl.Result{}, nil
	}

	keyServer := r.registry.GetPlugin(r.pluginName)
	if keyServer == nil || !keyServer.IsReady() {
		// TODO(avalluri): Update the QA status with the appropriate message
		l.Info("Plugin is not ready yet, will retry", "keyServer", r.pluginName)
		return ctrl.Result{Requeue: true}, nil
	}

	defer patchStatus()

	if qa.Spec.Type == tcsapi.RequestTypeQuoteAttestation {
		if ok, err := keyServer.AttestQuote(ctx, qa.Spec.SignerName, qa.Spec.Quote, qa.Spec.PublicKey, qa.Spec.Nonce); err != nil {
			l.Info("Error occurred while attesting quote", "error", err)
			qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionFalse, tcsapi.ReasonControllerReconcile, "Failed to attest: "+err.Error())
		} else if !ok {
			l.Info("Got quote verification failure")
			qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionFalse, tcsapi.ReasonControllerReconcile, "Provided quote was invalid.")
		} else {
			l.Info("Got quote verification success")
			qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "Quote verified successfully.")
		}
	} else if qa.Spec.Type == tcsapi.RequestTypeKeyProvisioning {
		if qa.Spec.SecretName == "" {
			qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionFalse, tcsapi.ReasonControllerReconcile, "Invalid request: missing secret name")
			return ctrl.Result{}, nil
		}
		wrappedData, cert, err := keyServer.GetCAKeyCertificate(ctx, qa.Spec.SignerName, qa.Spec.Quote, qa.Spec.PublicKey, qa.Spec.Nonce)
		if err != nil {
			err := fmt.Errorf("error from key server: %v", err)
			l.Info("Failed to fetch CA secrets", "signerName", qa.Spec.SignerName, "error", err)
			qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionFalse, tcsapi.ReasonControllerReconcile, err.Error())
			return ctrl.Result{Requeue: true}, nil
		}

		log.Log.Info("Preparing secret object", "signer", qa.Spec.SignerName, "secret", qa.Spec.SecretName)
		if err := createSecret(ctx, r.Client, wrappedData, cert, qa.Spec.SecretName, qa); err != nil {
			l.Info("Failed to create CA secret", "error", err)
			qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionFalse, tcsapi.ReasonControllerReconcile, err.Error())
			return ctrl.Result{}, nil
		}

		l.Info("Key wrapping SUCCESS")
		qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "CA secrets are prepared successfully.")
	} else {
		qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionFalse, tcsapi.ReasonControllerReconcile, "Unsupported request type")
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *QuoteAttestationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&tcsapi.QuoteAttestation{}).
		Watches(&source.Kind{Type: &tcsapi.QuoteAttestation{}}, &handler.EnqueueRequestForObject{}).
		WithEventFilter(predicate.Funcs{
			DeleteFunc: func(de event.DeleteEvent) bool {
				return false
			},
		}).
		Complete(r)
}

func (r *QuoteAttestationReconciler) CreateHandler(e event.CreateEvent, q workqueue.RateLimitingInterface) {
}

// secretNameForSigner returns the valid Kubernetes secret
// name for given signer:
//
//	<domain>[/signer-name] => tac-[signer-name.]domain
//
// Ex:
//
//	intel.com/sgx => tac-sgx.intel.com
//	clusterissuer.tcs.intel.com/test-ca => tac-test-ca.clusterissur.tcs.intel.com
func secretNameForSigner(signer string) string {
	secretName := "tac-" + signer
	slices := strings.SplitN(secretName, "/", 2)
	if len(slices) == 2 {
		return slices[1] + "." + slices[0]
	}

	return slices[0]
}

func createSecret(ctx context.Context, c client.Client, wrappedData, cert []byte, name string, owner *tcsapi.QuoteAttestation) error {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: owner.GetNamespace(),
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind:       owner.Kind,
					APIVersion: owner.APIVersion,
					Name:       owner.GetName(),
					UID:        owner.GetUID(),
				},
			},
		},
		Type: v1.SecretTypeOpaque,
		StringData: map[string]string{
			v1.TLSPrivateKeyKey: string(wrappedData),
			v1.TLSCertKey:       string(cert),
		},
	}
	err := c.Create(ctx, secret)
	if err != nil && errors.IsAlreadyExists(err) {
		return c.Update(ctx, secret)
	}
	return err
}
