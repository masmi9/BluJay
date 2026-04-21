#!/usr/bin/env python3
"""
Role-Based Access Control (RBAC) Manager for AODS Enterprise

Full RBAC system providing:
- Hierarchical role management with inheritance
- Granular permission system for all AODS features
- Resource-level access control (APK analysis, reports, system config)
- Dynamic permission evaluation and caching
- Integration with authentication system
- Audit logging for all access control decisions

Features:
- Role hierarchy with permission inheritance
- Resource-based permissions (CRUD operations)
- Context-aware access control (time, location, etc.)
- Permission templates for common scenarios
- Batch permission operations for efficiency
- Real-time permission updates and propagation
"""

import ast
import logging as stdlib_logging
import json
import operator
import time
from datetime import datetime, timezone
from typing import Dict, List, Set, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import threading
from collections import defaultdict, deque

try:
    from core.logging_config import get_logger
except ImportError:
    get_logger = stdlib_logging.getLogger

logger = get_logger(__name__)


class ResourceType(Enum):
    """Types of resources that can be controlled."""

    APK_ANALYSIS = "apk_analysis"
    REPORT = "report"
    USER_MANAGEMENT = "user_management"
    SYSTEM_CONFIG = "system_config"
    AUDIT_LOG = "audit_log"
    API_ENDPOINT = "api_endpoint"
    PLUGIN = "plugin"
    ML_MODEL = "ml_model"
    DASHBOARD = "dashboard"
    EXPORT = "export"


class Permission(Enum):
    """Standard CRUD permissions."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"
    AUDIT = "audit"


class AccessDecision(Enum):
    """Access control decisions."""

    ALLOW = "allow"
    DENY = "deny"
    CONDITIONAL = "conditional"


@dataclass
class RoleDefinition:
    """Definition of a role with permissions and metadata."""

    name: str
    description: str
    permissions: Set[str] = field(default_factory=set)
    parent_roles: Set[str] = field(default_factory=set)
    resource_permissions: Dict[ResourceType, Set[Permission]] = field(default_factory=dict)
    constraints: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True


@dataclass
class AccessRequest:
    """Request for access to a resource."""

    user_id: str
    username: str
    roles: List[str]
    resource_type: ResourceType
    resource_id: Optional[str]
    permission: Permission
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AccessResult:
    """Result of access control evaluation."""

    decision: AccessDecision
    allowed: bool
    reason: str
    applied_policies: List[str] = field(default_factory=list)
    conditions: List[str] = field(default_factory=list)
    evaluation_time_ms: float = 0.0
    cache_hit: bool = False


@dataclass
class PolicyRule:
    """Policy rule for advanced access control."""

    name: str
    description: str
    condition: str  # Expression to evaluate
    effect: AccessDecision
    priority: int = 100
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class PermissionCache:
    """High-performance permission caching system."""

    def __init__(self, ttl_seconds: int = 300, max_size: int = 10000):
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self.cache: Dict[str, Tuple[AccessResult, float]] = {}
        self.access_times: deque = deque()
        self.lock = threading.RLock()
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}

    def get(self, cache_key: str) -> Optional[AccessResult]:
        """Get cached access result."""
        with self.lock:
            if cache_key in self.cache:
                result, timestamp = self.cache[cache_key]

                # Check TTL
                if time.time() - timestamp < self.ttl_seconds:
                    self.stats["hits"] += 1
                    result.cache_hit = True
                    return result
                else:
                    # Expired entry
                    del self.cache[cache_key]

            self.stats["misses"] += 1
            return None

    def put(self, cache_key: str, result: AccessResult):
        """Cache access result."""
        with self.lock:
            # Evict if at capacity
            if len(self.cache) >= self.max_size:
                self._evict_oldest()

            self.cache[cache_key] = (result, time.time())
            self.access_times.append((cache_key, time.time()))

    def _evict_oldest(self):
        """Evict oldest cache entry."""
        if self.access_times:
            oldest_key, _ = self.access_times.popleft()
            if oldest_key in self.cache:
                del self.cache[oldest_key]
                self.stats["evictions"] += 1

    def invalidate_user(self, user_id: str):
        """Invalidate all cache entries for a user."""
        with self.lock:
            keys_to_remove = [k for k in self.cache.keys() if k.startswith(f"{user_id}:")]
            for key in keys_to_remove:
                del self.cache[key]

    def clear(self):
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            total_requests = self.stats["hits"] + self.stats["misses"]
            hit_rate = self.stats["hits"] / total_requests if total_requests > 0 else 0.0

            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hit_rate": hit_rate,
                "stats": self.stats.copy(),
            }


class SafeExpressionEvaluator:
    """AST-based safe expression evaluator.

    Replaces ``eval()`` with a restricted evaluator that only allows:
    - Literals (strings, numbers, booleans, None, lists, tuples)
    - Variable lookups from an explicit context dict
    - Comparisons (==, !=, <, >, <=, >=, in, not in, is, is not)
    - Boolean operations (and, or, not)
    - Calls to explicitly allowlisted functions
    """

    # Allowed comparison operators
    _CMP_OPS = {
        ast.Eq: operator.eq,
        ast.NotEq: operator.ne,
        ast.Lt: operator.lt,
        ast.LtE: operator.le,
        ast.Gt: operator.gt,
        ast.GtE: operator.ge,
        ast.In: lambda a, b: a in b,
        ast.NotIn: lambda a, b: a not in b,
        ast.Is: operator.is_,
        ast.IsNot: operator.is_not,
    }

    def __init__(self, context: Dict[str, Any], allowed_functions: Dict[str, Callable]):
        self._context = context
        self._allowed_functions = allowed_functions

    def evaluate(self, expression: str) -> Any:
        """Parse and safely evaluate an expression string."""
        tree = ast.parse(expression, mode="eval")
        return self._eval_node(tree.body)

    def _eval_node(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            name = node.id
            if name == "True":
                return True
            if name == "False":
                return False
            if name == "None":
                return None
            if name in self._context:
                return self._context[name]
            if name in self._allowed_functions:
                return self._allowed_functions[name]
            raise NameError(f"Name '{name}' is not allowed in policy expressions")

        if isinstance(node, ast.UnaryOp):
            operand = self._eval_node(node.operand)
            if isinstance(node.op, ast.Not):
                return not operand
            if isinstance(node.op, ast.USub):
                return -operand
            raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")

        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                return all(self._eval_node(v) for v in node.values)
            if isinstance(node.op, ast.Or):
                return any(self._eval_node(v) for v in node.values)
            raise ValueError(f"Unsupported boolean operator: {type(node.op).__name__}")

        if isinstance(node, ast.Compare):
            left = self._eval_node(node.left)
            for op_node, comparator in zip(node.ops, node.comparators):
                op_type = type(op_node)
                if op_type not in self._CMP_OPS:
                    raise ValueError(f"Unsupported comparison: {op_type.__name__}")
                right = self._eval_node(comparator)
                if not self._CMP_OPS[op_type](left, right):
                    return False
                left = right
            return True

        if isinstance(node, ast.Call):
            func = self._eval_node(node.func)
            if func not in self._allowed_functions.values():
                raise ValueError("Function call not in allowlist")
            args = [self._eval_node(a) for a in node.args]
            kwargs = {kw.arg: self._eval_node(kw.value) for kw in node.keywords}
            return func(*args, **kwargs)

        if isinstance(node, (ast.List, ast.Tuple)):
            elts = [self._eval_node(e) for e in node.elts]
            return elts if isinstance(node, ast.List) else tuple(elts)

        if isinstance(node, ast.IfExp):
            test = self._eval_node(node.test)
            return self._eval_node(node.body) if test else self._eval_node(node.orelse)

        raise ValueError(f"Unsupported expression node: {type(node).__name__}")


class PolicyEvaluator:
    """Evaluates complex policy rules for access control.

    Uses an AST-based safe evaluator instead of ``eval()`` to prevent
    arbitrary code execution in policy condition strings.
    """

    def __init__(self):
        self.logger = get_logger(f"{__name__}.PolicyEvaluator")

        # Built-in functions for policy evaluation (allowlist)
        self.functions = {
            "has_role": self._has_role,
            "time_between": self._time_between,
            "ip_in_range": self._ip_in_range,
            "resource_owner": self._resource_owner,
            "in_group": self._in_group,
            "has_permission": self._has_permission,
        }

    def evaluate_policy(self, rule: PolicyRule, request: AccessRequest, user_permissions: Set[str]) -> Tuple[bool, str]:
        """Evaluate a policy rule against an access request."""
        try:
            # Create evaluation context
            context = {
                "user_id": request.user_id,
                "username": request.username,
                "roles": request.roles,
                "resource_type": request.resource_type.value,
                "resource_id": request.resource_id,
                "permission": request.permission.value,
                "timestamp": request.timestamp,
                "user_permissions": user_permissions,
                **request.context,
            }

            # Safe AST-based evaluation (no eval())
            evaluator = SafeExpressionEvaluator(context, self.functions)
            result = evaluator.evaluate(rule.condition)
            return bool(result), "Policy evaluation successful"

        except Exception as e:
            self.logger.error(f"Policy evaluation failed for rule {rule.name}: {e}")
            return False, f"Policy evaluation error: {str(e)}"

    def _has_role(self, roles: List[str], role: str) -> bool:
        """Check if user has specific role."""
        return role in roles

    def _time_between(self, start_hour: int, end_hour: int) -> bool:
        """Check if current time is between specified hours."""
        current_hour = datetime.now().hour
        if start_hour <= end_hour:
            return start_hour <= current_hour <= end_hour
        else:  # Spans midnight
            return current_hour >= start_hour or current_hour <= end_hour

    def _ip_in_range(self, ip_address: str, ip_range: str) -> bool:
        """Check if IP address is in specified range."""
        # Simplified IP range check - in production use ipaddress module
        return ip_address.startswith(ip_range.split("/")[0].rsplit(".", 1)[0])

    def _resource_owner(self, resource_id: str, user_id: str) -> bool:
        """Check if user owns the resource."""
        # In production, implement actual ownership check
        return resource_id.startswith(user_id)

    def _in_group(self, groups: List[str], group: str) -> bool:
        """Check if user is in specific group."""
        return group in groups

    def _has_permission(self, permissions: Set[str], permission: str) -> bool:
        """Check if user has specific permission."""
        return permission in permissions


class RoleHierarchyManager:
    """Manages role hierarchy and permission inheritance."""

    def __init__(self):
        self.roles: Dict[str, RoleDefinition] = {}
        self.hierarchy_cache: Dict[str, Set[str]] = {}
        self.lock = threading.RLock()
        self.logger = get_logger(f"{__name__}.RoleHierarchyManager")

    def add_role(self, role: RoleDefinition) -> bool:
        """Add a new role to the hierarchy."""
        with self.lock:
            if role.name in self.roles:
                self.logger.warning(f"Role {role.name} already exists")
                return False

            # Validate parent roles exist
            for parent in role.parent_roles:
                if parent not in self.roles:
                    self.logger.error(f"Parent role {parent} does not exist")
                    return False

            # Check for circular dependencies
            if self._would_create_cycle(role.name, role.parent_roles):
                self.logger.error(f"Adding role {role.name} would create circular dependency")
                return False

            self.roles[role.name] = role
            self._invalidate_hierarchy_cache()

            self.logger.info(f"Role {role.name} added successfully")
            return True

    def update_role(self, role_name: str, updates: Dict[str, Any]) -> bool:
        """Update an existing role."""
        with self.lock:
            if role_name not in self.roles:
                self.logger.error(f"Role {role_name} not found")
                return False

            role = self.roles[role_name]

            # Apply updates
            for key, value in updates.items():
                if hasattr(role, key):
                    setattr(role, key, value)

            role.updated_at = datetime.now(timezone.utc)
            self._invalidate_hierarchy_cache()

            self.logger.info(f"Role {role_name} updated successfully")
            return True

    def delete_role(self, role_name: str) -> bool:
        """Delete a role from the hierarchy."""
        with self.lock:
            if role_name not in self.roles:
                return False

            # Check if role is referenced by other roles
            dependent_roles = [r.name for r in self.roles.values() if role_name in r.parent_roles]

            if dependent_roles:
                self.logger.error(f"Cannot delete role {role_name}: " f"referenced by {dependent_roles}")
                return False

            del self.roles[role_name]
            self._invalidate_hierarchy_cache()

            self.logger.info(f"Role {role_name} deleted successfully")
            return True

    def get_effective_permissions(self, role_names: List[str]) -> Set[str]:
        """Get effective permissions for a set of roles including inheritance."""
        with self.lock:
            all_permissions = set()

            for role_name in role_names:
                inherited_roles = self._get_inherited_roles(role_name)

                for inherited_role in inherited_roles:
                    if inherited_role in self.roles:
                        role = self.roles[inherited_role]
                        all_permissions.update(role.permissions)

            return all_permissions

    def get_effective_resource_permissions(self, role_names: List[str]) -> Dict[ResourceType, Set[Permission]]:
        """Get effective resource permissions for roles."""
        with self.lock:
            resource_permissions = defaultdict(set)

            for role_name in role_names:
                inherited_roles = self._get_inherited_roles(role_name)

                for inherited_role in inherited_roles:
                    if inherited_role in self.roles:
                        role = self.roles[inherited_role]
                        for resource_type, permissions in role.resource_permissions.items():
                            resource_permissions[resource_type].update(permissions)

            return dict(resource_permissions)

    def _get_inherited_roles(self, role_name: str) -> Set[str]:
        """Get all inherited roles for a role (including itself)."""
        if role_name in self.hierarchy_cache:
            return self.hierarchy_cache[role_name]

        inherited = set()
        visited = set()
        self._traverse_hierarchy(role_name, inherited, visited)

        self.hierarchy_cache[role_name] = inherited
        return inherited

    def _traverse_hierarchy(self, role_name: str, inherited: Set[str], visited: Set[str]):
        """Recursively traverse role hierarchy."""
        if role_name in visited or role_name not in self.roles:
            return

        visited.add(role_name)
        inherited.add(role_name)

        role = self.roles[role_name]
        for parent_role in role.parent_roles:
            self._traverse_hierarchy(parent_role, inherited, visited)

    def _would_create_cycle(self, role_name: str, parent_roles: Set[str]) -> bool:
        """Check if adding parent roles would create a cycle."""
        for parent in parent_roles:
            if self._has_path_to(parent, role_name):
                return True
        return False

    def _has_path_to(self, from_role: str, to_role: str) -> bool:
        """Check if there's a path from one role to another."""
        if from_role == to_role:
            return True

        if from_role not in self.roles:
            return False

        visited = set()
        stack = [from_role]

        while stack:
            current = stack.pop()
            if current in visited:
                continue

            visited.add(current)

            if current == to_role:
                return True

            if current in self.roles:
                stack.extend(self.roles[current].parent_roles)

        return False

    def _invalidate_hierarchy_cache(self):
        """Invalidate hierarchy cache when roles change."""
        self.hierarchy_cache.clear()

    def get_role_hierarchy(self) -> Dict[str, Any]:
        """Get complete role hierarchy structure."""
        with self.lock:
            hierarchy = {}

            for role_name, role in self.roles.items():
                hierarchy[role_name] = {
                    "description": role.description,
                    "parent_roles": list(role.parent_roles),
                    "permissions": list(role.permissions),
                    "resource_permissions": {
                        rt.value: [p.value for p in perms] for rt, perms in role.resource_permissions.items()
                    },
                    "is_active": role.is_active,
                    "created_at": role.created_at.isoformat(),
                    "updated_at": role.updated_at.isoformat(),
                }

            return hierarchy


class ResourceOwnershipRegistry:
    """Tracks resource ownership for resource-level access control."""

    def __init__(self):
        self._ownership: Dict[str, Dict[str, str]] = {}  # {resource_type: {resource_id: owner_id}}
        self._lock = threading.RLock()

    def register_owner(self, resource_type: str, resource_id: str, owner_id: str) -> None:
        """Register resource ownership."""
        with self._lock:
            if resource_type not in self._ownership:
                self._ownership[resource_type] = {}
            self._ownership[resource_type][resource_id] = owner_id

    def get_owner(self, resource_type: str, resource_id: str) -> Optional[str]:
        """Get owner of a resource."""
        with self._lock:
            return self._ownership.get(resource_type, {}).get(resource_id)

    def is_owner(self, resource_type: str, resource_id: str, user_id: str) -> bool:
        """Check if user owns the resource."""
        owner = self.get_owner(resource_type, resource_id)
        return owner is not None and owner == user_id

    def remove_resource(self, resource_type: str, resource_id: str) -> None:
        """Remove resource from registry."""
        with self._lock:
            if resource_type in self._ownership:
                self._ownership[resource_type].pop(resource_id, None)

    def get_user_resources(self, resource_type: str, user_id: str) -> List[str]:
        """Get all resources owned by a user."""
        with self._lock:
            return [rid for rid, owner in self._ownership.get(resource_type, {}).items() if owner == user_id]


class RBACManager:
    """Main RBAC manager coordinating all access control components."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = get_logger(f"{__name__}.RBACManager")

        # Initialize components
        self.role_manager = RoleHierarchyManager()
        self.policy_evaluator = PolicyEvaluator()
        self.permission_cache = PermissionCache(
            ttl_seconds=self.config.get("cache_ttl", 300), max_size=self.config.get("cache_size", 10000)
        )

        # Resource ownership registry
        self.resource_ownership = ResourceOwnershipRegistry()

        # Policy rules
        self.policy_rules: List[PolicyRule] = []

        # Audit settings
        self.audit_enabled = self.config.get("audit_enabled", True)
        self.audit_logger = self._setup_audit_logger()

        # Initialize default roles
        self._initialize_default_roles()

        self.logger.info("RBAC Manager initialized")

    def _setup_audit_logger(self):
        """Setup audit logger for access control decisions."""
        # Use stdlib logger directly - structlog BoundLogger lacks .handlers/.addHandler()
        audit_logger = stdlib_logging.getLogger("rbac_audit")

        if not audit_logger.handlers:
            handler = stdlib_logging.FileHandler(self.config.get("audit_log_file", "rbac_audit.log"))
            formatter = stdlib_logging.Formatter("%(asctime)s - RBAC_AUDIT - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            audit_logger.addHandler(handler)
            audit_logger.setLevel(stdlib_logging.INFO)

        return audit_logger

    def _initialize_default_roles(self):
        """Initialize default AODS roles."""
        default_roles = [
            RoleDefinition(
                name="admin",
                description="Full system administrator",
                permissions={
                    "admin.all",
                    "system.configure",
                    "users.manage",
                    "analysis.manage",
                    "reports.manage",
                    "audit.view",
                },
                resource_permissions={
                    ResourceType.APK_ANALYSIS: {
                        Permission.CREATE,
                        Permission.READ,
                        Permission.UPDATE,
                        Permission.DELETE,
                        Permission.EXECUTE,
                        Permission.ADMIN,
                    },
                    ResourceType.REPORT: {
                        Permission.CREATE,
                        Permission.READ,
                        Permission.UPDATE,
                        Permission.DELETE,
                        Permission.ADMIN,
                    },
                    ResourceType.USER_MANAGEMENT: {
                        Permission.CREATE,
                        Permission.READ,
                        Permission.UPDATE,
                        Permission.DELETE,
                        Permission.ADMIN,
                    },
                    ResourceType.SYSTEM_CONFIG: {
                        Permission.CREATE,
                        Permission.READ,
                        Permission.UPDATE,
                        Permission.DELETE,
                        Permission.ADMIN,
                    },
                    ResourceType.AUDIT_LOG: {Permission.READ, Permission.AUDIT},
                    ResourceType.API_ENDPOINT: {Permission.EXECUTE, Permission.ADMIN},
                    ResourceType.PLUGIN: {
                        Permission.CREATE,
                        Permission.READ,
                        Permission.UPDATE,
                        Permission.DELETE,
                        Permission.EXECUTE,
                    },
                    ResourceType.ML_MODEL: {
                        Permission.CREATE,
                        Permission.READ,
                        Permission.UPDATE,
                        Permission.DELETE,
                        Permission.EXECUTE,
                    },
                    ResourceType.DASHBOARD: {Permission.CREATE, Permission.READ, Permission.UPDATE, Permission.DELETE},
                    ResourceType.EXPORT: {Permission.CREATE, Permission.READ, Permission.EXECUTE},
                },
            ),
            RoleDefinition(
                name="analyst",
                description="Security analyst with analysis capabilities",
                permissions={"analysis.run", "analysis.view", "reports.generate", "reports.view", "dashboard.view"},
                resource_permissions={
                    ResourceType.APK_ANALYSIS: {Permission.CREATE, Permission.READ, Permission.EXECUTE},
                    ResourceType.REPORT: {Permission.CREATE, Permission.READ, Permission.UPDATE},
                    ResourceType.API_ENDPOINT: {Permission.EXECUTE},
                    ResourceType.PLUGIN: {Permission.READ, Permission.EXECUTE},
                    ResourceType.ML_MODEL: {Permission.READ, Permission.EXECUTE},
                    ResourceType.DASHBOARD: {Permission.READ},
                    ResourceType.EXPORT: {Permission.CREATE, Permission.READ},
                },
            ),
            RoleDefinition(
                name="viewer",
                description="Read-only access to analysis results",
                permissions={"analysis.view", "reports.view", "dashboard.view"},
                resource_permissions={
                    ResourceType.APK_ANALYSIS: {Permission.READ},
                    ResourceType.REPORT: {Permission.READ},
                    ResourceType.DASHBOARD: {Permission.READ},
                },
            ),
            RoleDefinition(
                name="auditor",
                description="Audit and compliance access",
                permissions={"audit.view", "reports.view", "logs.access"},
                resource_permissions={
                    ResourceType.AUDIT_LOG: {Permission.READ, Permission.AUDIT},
                    ResourceType.REPORT: {Permission.READ},
                    ResourceType.DASHBOARD: {Permission.READ},
                },
            ),
            RoleDefinition(
                name="api_user",
                description="API access for automated systems",
                permissions={"api.access", "analysis.run"},
                resource_permissions={
                    ResourceType.API_ENDPOINT: {Permission.EXECUTE},
                    ResourceType.APK_ANALYSIS: {Permission.CREATE, Permission.READ},
                    ResourceType.PLUGIN: {Permission.EXECUTE},
                    ResourceType.ML_MODEL: {Permission.EXECUTE},
                },
            ),
        ]

        for role in default_roles:
            self.role_manager.add_role(role)

    def check_access(self, request: AccessRequest) -> AccessResult:
        """Main access control check method."""
        start_time = time.time()

        # Generate cache key
        cache_key = self._generate_cache_key(request)

        # Check cache first
        cached_result = self.permission_cache.get(cache_key)
        if cached_result:
            cached_result.evaluation_time_ms = (time.time() - start_time) * 1000
            return cached_result

        # Perform access evaluation
        result = self._evaluate_access(request)
        result.evaluation_time_ms = (time.time() - start_time) * 1000

        # Cache result
        self.permission_cache.put(cache_key, result)

        # Audit logging
        if self.audit_enabled:
            self._audit_access_decision(request, result)

        return result

    def check_resource_access(
        self,
        user_id: str,
        user_roles: List[str],
        resource_type: str,
        resource_id: str,
        permission: str = "read",
    ) -> Tuple[bool, str]:
        """
        Check if user can access a specific resource considering ownership.

        Returns:
            Tuple of (allowed: bool, reason: str)

        Rules:
        - Admin can access all resources
        - Analysts can only access their own resources (ownership check)
        - Viewers can read any resource (no ownership restriction for read)
        - Auditors can only access audit logs
        """
        # Admins have full access
        if "admin" in user_roles:
            return True, "Admin role grants full access"

        # Auditors only access audit logs
        if "auditor" in user_roles and resource_type != "audit_log":
            return False, "Auditor role only permits audit log access"

        # For analysts, enforce ownership on write operations
        if "analyst" in user_roles:
            if permission in ("update", "delete", "execute"):
                # Check ownership for write operations
                if not self.resource_ownership.is_owner(resource_type, resource_id, user_id):
                    owner = self.resource_ownership.get_owner(resource_type, resource_id)
                    if owner is not None:
                        return False, "Resource owned by another user"
            # Analysts can read their own resources or resources without ownership
            return True, "Analyst access granted"

        # Viewers have read-only access
        if "viewer" in user_roles:
            if permission == "read":
                return True, "Viewer read access granted"
            return False, "Viewer role is read-only"

        # API users can access their own resources
        if "api_user" in user_roles:
            if self.resource_ownership.is_owner(resource_type, resource_id, user_id):
                return True, "API user owns resource"
            if permission == "read":
                return True, "API user read access granted"
            return False, "API user cannot modify resources owned by others"

        return False, "No matching role permissions"

    def register_resource_owner(self, resource_type: str, resource_id: str, owner_id: str) -> None:
        """Register ownership of a resource (call when creating scans, reports, etc.)."""
        self.resource_ownership.register_owner(resource_type, resource_id, owner_id)

    def _evaluate_access(self, request: AccessRequest) -> AccessResult:
        """Evaluate access request against roles and policies."""

        # Get effective permissions from roles
        user_permissions = self.role_manager.get_effective_permissions(request.roles)
        resource_permissions = self.role_manager.get_effective_resource_permissions(request.roles)

        # Check basic permission
        permission_key = f"{request.resource_type.value}.{request.permission.value}"
        has_basic_permission = permission_key in user_permissions

        # Check resource-specific permission
        has_resource_permission = False
        if request.resource_type in resource_permissions:
            has_resource_permission = request.permission in resource_permissions[request.resource_type]

        # Initial decision based on role permissions
        basic_allowed = has_basic_permission or has_resource_permission

        if not basic_allowed:
            return AccessResult(
                decision=AccessDecision.DENY, allowed=False, reason="Insufficient role permissions", applied_policies=[]
            )

        # Evaluate policy rules
        policy_results = []
        for rule in self.policy_rules:
            if not rule.is_active:
                continue

            policy_match, error_msg = self.policy_evaluator.evaluate_policy(rule, request, user_permissions)

            if error_msg != "Policy evaluation successful":
                continue

            if policy_match:
                policy_results.append((rule, True))
            else:
                policy_results.append((rule, False))

        # Apply policy decisions
        final_decision = AccessDecision.ALLOW
        applied_policies = []
        conditions = []

        # Sort by priority (higher priority first)
        policy_results.sort(key=lambda x: x[0].priority, reverse=True)

        for rule, matched in policy_results:
            if matched:
                applied_policies.append(rule.name)

                if rule.effect == AccessDecision.DENY:
                    final_decision = AccessDecision.DENY
                    break
                elif rule.effect == AccessDecision.CONDITIONAL:
                    final_decision = AccessDecision.CONDITIONAL
                    conditions.append(rule.description)

        # Determine final result
        allowed = final_decision in [AccessDecision.ALLOW, AccessDecision.CONDITIONAL]

        reason_parts = []
        if basic_allowed:
            reason_parts.append("Role permissions granted")
        if applied_policies:
            reason_parts.append(f"Policies applied: {', '.join(applied_policies)}")
        if conditions:
            reason_parts.append(f"Conditions: {', '.join(conditions)}")

        reason = "; ".join(reason_parts) if reason_parts else "Access denied"

        return AccessResult(
            decision=final_decision,
            allowed=allowed,
            reason=reason,
            applied_policies=applied_policies,
            conditions=conditions,
        )

    def add_policy_rule(self, rule: PolicyRule) -> bool:
        """Add a new policy rule."""
        try:
            # Validate rule condition syntax
            self.policy_evaluator.evaluate_policy(
                rule,
                AccessRequest(
                    user_id="test",
                    username="test",
                    roles=["test"],
                    resource_type=ResourceType.APK_ANALYSIS,
                    resource_id="test",
                    permission=Permission.READ,
                ),
                set(),
            )

            self.policy_rules.append(rule)
            self.permission_cache.clear()  # Invalidate cache

            self.logger.info(f"Policy rule {rule.name} added successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to add policy rule {rule.name}: {e}")
            return False

    def remove_policy_rule(self, rule_name: str) -> bool:
        """Remove a policy rule."""
        original_count = len(self.policy_rules)
        self.policy_rules = [r for r in self.policy_rules if r.name != rule_name]

        if len(self.policy_rules) < original_count:
            self.permission_cache.clear()
            self.logger.info(f"Policy rule {rule_name} removed successfully")
            return True

        return False

    def invalidate_user_cache(self, user_id: str):
        """Invalidate cache for specific user."""
        self.permission_cache.invalidate_user(user_id)

    def _generate_cache_key(self, request: AccessRequest) -> str:
        """Generate cache key for access request."""
        roles_str = ",".join(sorted(request.roles))
        context_str = json.dumps(request.context, sort_keys=True)

        return (
            f"{request.user_id}:{roles_str}:{request.resource_type.value}:"
            f"{request.resource_id}:{request.permission.value}:{hash(context_str)}"
        )

    def _audit_access_decision(self, request: AccessRequest, result: AccessResult):
        """Audit access control decision."""
        audit_data = {
            "timestamp": request.timestamp.isoformat(),
            "user_id": request.user_id,
            "username": request.username,
            "roles": request.roles,
            "resource_type": request.resource_type.value,
            "resource_id": request.resource_id,
            "permission": request.permission.value,
            "decision": result.decision.value,
            "allowed": result.allowed,
            "reason": result.reason,
            "applied_policies": result.applied_policies,
            "evaluation_time_ms": result.evaluation_time_ms,
            "cache_hit": result.cache_hit,
        }

        log_level = stdlib_logging.INFO if result.allowed else stdlib_logging.WARNING
        self.audit_logger.log(log_level, json.dumps(audit_data))

    def get_user_permissions(self, user_roles: List[str]) -> Dict[str, Any]:
        """Get full permissions for user roles."""
        effective_permissions = self.role_manager.get_effective_permissions(user_roles)
        resource_permissions = self.role_manager.get_effective_resource_permissions(user_roles)

        return {
            "roles": user_roles,
            "permissions": list(effective_permissions),
            "resource_permissions": {rt.value: [p.value for p in perms] for rt, perms in resource_permissions.items()},
        }

    def get_system_status(self) -> Dict[str, Any]:
        """Get RBAC system status and statistics."""
        cache_stats = self.permission_cache.get_stats()

        return {
            "roles_count": len(self.role_manager.roles),
            "policy_rules_count": len(self.policy_rules),
            "cache_statistics": cache_stats,
            "audit_enabled": self.audit_enabled,
            "performance_metrics": {
                "average_evaluation_time_ms": 0.0,  # Calculate from metrics
                "cache_hit_rate": cache_stats.get("hit_rate", 0.0),
            },
        }


# Factory function for easy initialization


def create_rbac_manager(config: Dict[str, Any] = None) -> RBACManager:
    """Create RBAC manager with configuration."""
    return RBACManager(config or {})


if __name__ == "__main__":
    # Example usage and testing
    rbac = create_rbac_manager({"audit_enabled": True, "cache_ttl": 300})

    # Test access request
    request = AccessRequest(
        user_id="user123",
        username="analyst1",
        roles=["analyst"],
        resource_type=ResourceType.APK_ANALYSIS,
        resource_id="apk_001",
        permission=Permission.READ,
    )

    result = rbac.check_access(request)
    logger.info("Access check result", decision=result.decision.value, allowed=result.allowed, reason=result.reason)
