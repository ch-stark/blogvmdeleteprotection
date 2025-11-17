## 🛡️ Unbreakable VMs: Using ACM Policies and Gatekeeper to Enforce and Protect Delete Protection for Virtual Machines

Virtual Machines (VMs) often host critical workloads, and the `accidental deletion` of a VM can be catastrophic. If you are a VM user, ensuring that your VM does not get deleted *unintentionally* is a high priority.

While **OpenShift Virtualization** (KubeVirt) provides a built-in mechanism to prevent inadvertent VM deletion—called virtual machine delete protection—relying on manual configuration leaves room for human error. By default, this option is *disabled*, and it must be set individually for each VM.

This blog post outlines a powerful two-step policy approach using RHACM Policy and Gatekeeper to not only enforce delete protection universally but also strictly govern who is authorized to remove that protection.

The native OKD/KubeVirt feature is controlled by setting a specific label on the VirtualMachine resource: `kubevirt.io/vm-delete-protection`.

> **_NOTE:_**: this is available with OpenShift 4.19 onwards.


```yaml
Enable Delete Protection	oc patch vm <vm_name> --type merge -p '{"metadata":{"labels":{"kubevirt.io/vm-delete-protection":"True"}}}'
Disable Delete Protection	oc patch vm <vm_name> --type json -p '[{"op": "remove", "path": "/metadata/labels/kubevirt.io~1vm-delete-protection"}]'
```
Our goal is to automate the first action (**enabling**) and tightly control the second action (**disabling**).

### Step 1: Automated Enforcement using ACM Policy (Proactive)

The first step uses an ACM Policy to automatically ensure the delete protection label is set to `True` on all targeted VMs. In the first example we leverage the native capabilities of the ConfigurationPolicy to enforce the configuration directly on the VirtualMachine kind within specified namespaces.

By setting the `remediationAction` to enforce, the *Configuration Policy Controller* will automatically patch any VM missing or incorrectly setting the required label, instantly bringing it into compliance.

> **_NOTE:_**  You can certainly flexible specify on which kind of VM's you want to apply this setting

#### The ACM Policy Definition:

The ACM Policy uses `musthave` to enforce the delete-protection label

```yaml
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
  name: enforce-vm-delete-protection-label
  namespace: policies
  annotations:
    policy.open-cluster-management.io/categories: CM Configuration Management
    policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
    policy.open-cluster-management.io/standards: Custom
spec:
  # Crucial: 'enforce' for automatic patching
  remediationAction: enforce 
  disabled: false
  policy-templates:
  - objectDefinition:
      apiVersion: policy.open-cluster-management.io/v1
      kind: ConfigurationPolicy
      metadata:
        name: check-vm-delete-protection-label
      spec:
        remediationAction: enforce
        severity: low
        # Excludes common system namespaces from enforcement
        namespaceSelector:
          exclude: ["kube-*", "open-cluster-management", "openshift-*", "default", "cert-manager", "redhat-ods-applications"]
          matchLabels: {}
        # This example targets only VMs that have the label 'environment: production'.
        objectSelector:
          matchLabels:
            environment: "production"
        # Simple object-templates to enforce the configuration on the target kind
        object-templates: 
          - complianceType: musthave
            objectDefinition:
              apiVersion: kubevirt.io/v1
              kind: VirtualMachine
              metadata:
                # By omitting 'name', this applies to all VMs in selected namespaces 
                labels:
                  kubevirt.io/vm-delete-protection: "True" # Enforce the label
```
(Placement and PlacementBinding are required to deploy the policy to managed clusters, but are omitted here for brevity.)

For more *fine-grained control* you can also the popular `policy-templating` feature:

```yaml
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
  name: enforce-vm-delete-protection-label
  namespace: policies
  annotations:
    policy.open-cluster-management.io/categories: CM Configuration Management
    policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
    policy.open-cluster-management.io/standards: Custom
spec:
  remediationAction: inform # Set to 'enforce' to automatically add the label [1, 7]
  disabled: false
  policy-templates:
    - objectDefinition:
        apiVersion: policy.open-cluster-management.io/v1
        kind: ConfigurationPolicy
        metadata:
          name: enforce-vm-delete-protection-label-templatized
        spec:
          remediationAction: inform # Overridden by parent policy [5, 6]
          severity: low
          namespaceSelector:
            # Excludes system namespaces, targeting namespaces for the loop [5, 6]
            exclude: ["kube-*", "open-cluster-management", "openshift-*", "default", "cert-manager", "redhat-ods-applications"]
            matchLabels: {}
          
          # 
          # THE LOOPING LOGIC IS BELOW IN object-templates-raw
          # 
          object-templates-raw: |
            {{- $namespaces := (lookup "v1" "Namespace" "" "" "").items }}
            {{- range $namespace := $namespaces }}
            {{- if not (or (hasPrefix "kube-" $namespace.metadata.name) (hasPrefix "open-cluster-management" $namespace.metadata.name) (hasPrefix "openshift-" $namespace.metadata.name) (eq "default" $namespace.metadata.name) (eq "cert-manager" $namespace.metadata.name) (eq "redhat-ods-applications" $namespace.metadata.name)) }}
            {{- $vms := (lookup "kubevirt.io/v1" "VirtualMachine" $namespace.metadata.name "" "").items }}
            {{- range $vm := $vms }}
            - complianceType: musthave
              objectDefinition:
                apiVersion: kubevirt.io/v1
                kind: VirtualMachine
                metadata:
                  name: {{ $vm.metadata.name }}
                  namespace: {{ $vm.metadata.namespace }}
                  labels:
                    kubevirt.io/vm-delete-protection: "True"
            {{- end }}
            {{- end }}
            {{- end }}
```

### Step 2: Restricted Management using Gatekeeper (Preventative)

Once the delete protection is universally applied by the ACM policy, we must ensure that only **authorized** personnel can disable it. This step uses Gatekeeper to create an admission controller policy that blocks updates attempting to remove the protection label, unless the user belongs to a specific administrative group.

This policy demonstrates a **powerful** principle: *Separation of Duties*. An automatic operator may apply the protection, but only a human administrator with special privileges can override it.

### 2.1 The Gatekeeper Constraint Template

```yaml
## File 1: ConstraintTemplate - k8sblockoperator (Revised Rego)

apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockoperator
spec:
  crd:
    spec:
      names:
        kind: K8sBlockOperator
      validation:
        openAPIV3Schema:
          type: object
          properties:
            blockedUser:
              type: string
              description: The user or ServiceAccount name to be blocked.
            requiredGroup:
              type: string
              description: The group required to bypass the restriction (e.g., 'supervmadmin').
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sblockoperator
        
        blocked_user := input.parameters.blockedUser
        required_group := input.parameters.requiredGroup
        user_groups := input.request.userInfo.groups
        current_user := input.request.userInfo.username
        
        # Helper to check if the user is an admin
        user_is_admin {
          user_groups[_] == required_group
        }
        
        # Helper to check if the delete protection label has been removed or modified from "True"
        protection_removed {
          old_labels := input.review.oldObject.metadata.labels
          new_labels := input.review.object.metadata.labels
          
          # 1. Protection was present and set to "True" in the old object
          old_labels["kubevirt.io/vm-delete-protection"] == "True"
          
          # 2. Protection is either gone OR set to anything other than "True" in the new object
          (not new_labels["kubevirt.io/vm-delete-protection"]) 
          or (new_labels["kubevirt.io/vm-delete-protection"] != "True")
        }
        
        # DENY RULE
        deny[{"msg": msg}] {
          # 1. Operation must be an UPDATE
          input.request.operation == "UPDATE"
          
          # 2. The requested update attempts to remove or disable the protection setting
          protection_removed
          
          # Generates denial message
          vm_name := input.review.oldObject.metadata.name
          msg := sprintf("Access Denied: User %v is not authorized to remove the delete protection label from VirtualMachine %v. Only members of the '%v' group can bypass this restriction.", [current_user, vm_name, required_group])
        }
```

### 2.2 The Gatekeeper Constraint

The Constraint applies the template, specifying which user is restricted and which group holds the required bypass privilege.

```yaml
# File 2: Sample Constraint - block-vm-operator

apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockOperator
metadata:
  name: block-vm-operator
spec:
  match:
    kinds:
      - apiGroups: ["kubevirt.io"]
        kinds: ["VirtualMachine"]
  parameters:
    # The required group that can bypass this block (e.g., your human admin group)
    requiredGroup: "supervmadmin" 
```

With this constraint in place, if the `cluster-admin` or any other user attempts to modify or remove the `kubevirt.io/vm-delete-protection` setting, the request will be denied unless the user also belongs to the **supervmadmin** group.

## 🔒 Summary: The Policy Shield

By combining ACM Policy for proactive enforcement and Gatekeeper for preventative control, VM users gain a robust safety net.
ACM ensures that the delete protection label `(kubevirt.io/vm-delete-protection: "True")` is automatically present on all non-system VMs, preventing accidental deletion.
Gatekeeper acts as the final lock, ensuring that only designated VM-Super-Admins are authorized to remove this crucial safety feature.

This system works like a security vault: ACM ensures every valuable item is always locked inside the vault, and Gatekeeper ensures that only the select few with the master key can unlock it.
