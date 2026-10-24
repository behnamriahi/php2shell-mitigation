#!/bin/bash
# PHP2Shell security audit and mitigation
# Target: CentOS/RHEL 7 and compatible Samfony EL7
# PHP: 5.4 package family
#
# Mitigation:
#   php_admin_value session.upload_progress.enabled 0
#
# IMPORTANT:
# This script applies a configuration mitigation, not a PHP patch.

set -u
umask 077

CONF="/etc/httpd/conf.d/php.conf"
CONFIG_STATUS="NOT VERIFIED"
CHANGE_MADE=0
BACKUP=""
TMP=""

log() {
    printf '%s\n' "$1"
}

cleanup() {
    if [ -n "${TMP:-}" ] && [ -f "$TMP" ]; then
        rm -f "$TMP"
    fi
}
trap cleanup EXIT

report() {
    echo
    echo "============================================================"
    echo "                 SECURITY REPORT"
    echo "============================================================"

    echo
    echo "[CVE-2026-109618] PHP request parsing / memory exhaustion"
    echo "  Package: PHP 5.4.16 EL7 package family"
    echo "  Assessment: The known RCE path is not reported as present"
    echo "  in the EL7 PHP 5.4 package analysis."
    echo "  Note: This script does not patch or independently prove"
    echo "  the absence of every possible impact, including DoS."
    echo "  The upload-progress setting does not fix this CVE."

    echo
    echo "[CVE-2026-109619] Stale request state / use-after-free"
    case "$CONFIG_STATUS" in
        ALREADY_SET)
            echo "  Result: MITIGATION ALREADY ACTIVE IN APACHE CONFIG."
            echo "  session.upload_progress.enabled is set to 0."
            echo "  No configuration change or Apache restart was needed."
            ;;
        APPLIED)
            echo "  Result: MITIGATION CONFIGURED."
            echo "  session.upload_progress.enabled is now set to 0."
            echo "  The known session upload-progress attack path is mitigated."
            ;;
        *)
            echo "  Result: MITIGATION NOT VERIFIED."
            echo "  Check Apache/PHP configuration and effective web PHP value."
            ;;
    esac
    echo "  Note: This is a mitigation, not an upstream PHP security patch."

    echo
    echo "[CVE-2026-115560] Session upload-progress RCE vector"
    case "$CONFIG_STATUS" in
        ALREADY_SET|APPLIED)
            echo "  Result: PROTECTED BY THE RECOMMENDED SETTING."
            echo "  session.upload_progress.enabled=0 disables the feature"
            echo "  required for this reported attack vector."
            ;;
        *)
            echo "  Result: PROTECTION NOT VERIFIED."
            ;;
    esac
    echo "  Note: This does not mean the PHP package itself is patched."

    echo
    echo "------------------------------------------------------------"
    echo "Configuration status : $CONFIG_STATUS"
    echo "Configuration changed: $CHANGE_MADE"
    if [ -n "$BACKUP" ]; then
        echo "Backup file          : $BACKUP"
    fi
    echo "PHP package:"
    rpm -q php 2>/dev/null || true
    echo "Apache package:"
    rpm -q httpd 2>/dev/null || true
    echo "------------------------------------------------------------"
    echo "This report assesses the listed issues only."
    echo "Plan an upgrade to a supported OS/PHP package."
    echo "============================================================"
}

fail() {
    log "[ERROR] $1"
    report
    exit 1
}

echo "=== PHP2Shell Security Audit and Mitigation ==="

# Root check
if [ "$(id -u)" -ne 0 ]; then
    log "[ERROR] Run as root."
    exit 1
fi

# Detect the OS and package family
PRETTY_NAME="unknown"
OS_ID=""
OS_MAJOR=""

if [ -r /etc/os-release ]; then
    . /etc/os-release
    PRETTY_NAME="${PRETTY_NAME:-unknown}"
    OS_ID="${ID:-}"
    OS_MAJOR="${VERSION_ID%%.*}"
fi

EL7_CONFIRMED=0

if [[ "$OS_ID" == "centos" || "$OS_ID" == "rhel" ||
      "$OS_ID" == "ol" || "$OS_ID" == "scientific" ]] &&
   [ "$OS_MAJOR" = "7" ]; then
    EL7_CONFIRMED=1
fi

# Support Samfony identifying itself as CentOS 7, but verify packages.
if [ "$EL7_CONFIRMED" -ne 1 ] &&
   [ -r /etc/centos-release ] &&
   grep -qE 'CentOS Linux release 7\.' /etc/centos-release &&
   rpm -q php httpd >/dev/null 2>&1 &&
   rpm -q php | grep -qE '\.el7([.]|$)' &&
   rpm -q httpd | grep -qE '\.el7([.]|$)'; then
    EL7_CONFIRMED=1
fi

if [ "$EL7_CONFIRMED" -ne 1 ]; then
    log "[SKIP] Unsupported OS/package combination: $PRETTY_NAME"
    log "[INFO] No configuration changes were made."
    report
    exit 0
fi

echo "[OK] OS: $PRETTY_NAME"
rpm -q php httpd || fail "Could not identify PHP/Apache RPM packages."

# Verify the installed Apache binary
command -v httpd >/dev/null 2>&1 ||
    fail "Apache httpd binary was not found."

# Verify mod_php is loaded
if ! httpd -M 2>&1 | grep -Eq 'php[0-9]*_module'; then
    log "[SKIP] Apache PHP module was not detected."
    log "[INFO] No configuration changes were made."
    report
    exit 0
fi

# Verify target configuration file
[ -f "$CONF" ] || fail "Configuration file not found: $CONF"

# Read active php_admin_value directives for this setting.
# Ignore comments. Remove optional quote characters around the value.
mapfile -t VALUES < <(
    awk '
    $1 !~ /^#/ &&
    tolower($1) == "php_admin_value" &&
    tolower($2) == "session.upload_progress.enabled" {
        value = $3
        gsub(/["\047]/, "", value)
        print tolower(value)
    }
    ' "$CONF"
)

# IDEMPOTENCY:
# If exactly one active directive is already set to 0,
# do not create a backup, rewrite the file, or restart Apache.
if [ "${#VALUES[@]}" -eq 1 ] && [ "${VALUES[0]}" = "0" ]; then
    log "[OK] Mitigation is already configured exactly once."

    if ! httpd -t; then
        CONFIG_STATUS="ALREADY_SET"
        fail "The setting exists, but Apache configuration validation failed."
    fi

    CONFIG_STATUS="ALREADY_SET"
    CHANGE_MADE=0

    log "[OK] Apache configuration syntax is valid."
    log "[INFO] No backup created; no file changed; no restart performed."
    report
    exit 0
fi

# Prepare a normalized configuration only when a change is necessary.
TMP="$(mktemp /etc/httpd/conf.d/.php.conf.tmp.XXXXXX)" ||
    fail "Could not create temporary configuration file."

if ! awk '
{
    lower = tolower($0)

    # Remove active copies of the target directive.
    if ($1 !~ /^#/ &&
        tolower($1) == "php_admin_value" &&
        tolower($2) == "session.upload_progress.enabled") {
        next
    }

    # Avoid accumulating comments created by this script.
    if (lower ~ /^[[:space:]]*#[[:space:]]*security mitigation: disable php session upload progress[[:space:]]*$/) {
        next
    }
    if (lower ~ /^[[:space:]]*#[[:space:]]*security mitigation for php session upload-progress vulnerabilities[[:space:]]*$/) {
        next
    }

    print
}
END {
    print ""
    print "# Security mitigation: disable PHP session upload progress"
    print "php_admin_value session.upload_progress.enabled 0"
}
' "$CONF" > "$TMP"; then
    fail "Could not prepare updated configuration."
fi

# Preserve original owner and permissions.
chown --reference="$CONF" "$TMP" ||
    fail "Could not preserve configuration ownership."
chmod --reference="$CONF" "$TMP" ||
    fail "Could not preserve configuration permissions."

# Re-check in case the normalized output is identical.
if cmp -s "$CONF" "$TMP"; then
    CONFIG_STATUS="ALREADY_SET"
    CHANGE_MADE=0
    log "[OK] Configuration already matches the desired state."
    log "[INFO] No restart performed."
    report
    exit 0
fi

# Create a backup only when a real change is required.
BACKUP="${CONF}.bak.$(date +%Y%m%d-%H%M%S)"
cp -a "$CONF" "$BACKUP" ||
    fail "Could not create backup."

log "[INFO] Backup created: $BACKUP"

# Apply the prepared configuration.
if ! cat "$TMP" > "$CONF"; then
    cp -a "$BACKUP" "$CONF" ||
        log "[CRITICAL] Could not restore the backup automatically."
    CONFIG_STATUS="NOT VERIFIED"
    fail "Could not write updated configuration."
fi

# Validate before restarting Apache.
if ! httpd -t; then
    cp -a "$BACKUP" "$CONF" ||
        log "[CRITICAL] Could not restore the backup automatically."
    CONFIG_STATUS="NOT VERIFIED"
    fail "Apache configuration validation failed; attempted rollback."
fi

log "[OK] Apache configuration syntax is valid."

# Restart only after a real change and successful syntax validation.
if systemctl restart httpd; then
    CONFIG_STATUS="APPLIED"
    CHANGE_MADE=1
    log "[SUCCESS] Apache restarted after a configuration change."
else
    log "[ERROR] Apache restart failed; restoring the backup."

    if cp -a "$BACKUP" "$CONF" && httpd -t && systemctl restart httpd; then
        log "[INFO] Original configuration restored and Apache restarted."
    else
        log "[CRITICAL] Automatic recovery failed."
        log "[CRITICAL] Inspect Apache service immediately."
        log "[CRITICAL] Backup: $BACKUP"
    fi

    CONFIG_STATUS="NOT VERIFIED"
    CHANGE_MADE=1
    report
    exit 1
fi

report
exit 0
