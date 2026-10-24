# PHP2Shell Security Mitigation for Legacy PHP / Apache

This repository provides a defensive configuration mitigation for PHP deployments that use Apache `mod_php` and are affected by session upload-progress attack paths.

> **Important:** Disabling session upload progress is a mitigation, not a PHP security update. It does not replace upgrading PHP and the operating system to supported, patched releases.

## Contents

- [Scope and limitations](#scope-and-limitations)
- [What the script does](#what-the-script-does)
- [CVE assessment](#cve-assessment)
- [Automated installation](#automated-installation)
- [Manual configuration](#manual-configuration)
- [Verification](#verification)
- [Rollback](#rollback)
- [Additional PHP hardening](#additional-php-hardening)
- [Systems other than RHEL-compatible EL7](#systems-other-than-rhel-compatible-el7)
- [Troubleshooting](#troubleshooting)
- [References](#references)

## Scope and limitations

The script was designed and tested against this package family:

- CentOS 7 / compatible EL7 derivatives
- PHP RPM package family: `php-5.4.16-48.el7`
- Apache HTTP Server package family: `httpd-2.4.6-98.el7.centos.7`
- Apache `mod_php`

A custom distribution may identify itself differently in `/etc/os-release` while retaining CentOS 7 package metadata. The script checks the OS and installed RPM package family before changing configuration.

**Do not assume that the same CVE assessment applies to every PHP version, vendor build, operating system, or downstream package.** Check the security advisory for your exact vendor and package release.

The script modifies `/etc/httpd/conf.d/php.conf`. It does not patch binaries, update RPM packages, or independently scan the application for compromise.

## What the script does

When run as root, `test.sh`:

1. Checks whether the operating system and PHP/Apache package family are supported.
2. Confirms that Apache and its PHP module are available.
3. Checks the active `php_admin_value session.upload_progress.enabled` directives in `/etc/httpd/conf.d/php.conf`.
4. If exactly one active directive already sets the value to `0`, it validates Apache syntax and exits **without changing the file, creating a backup, or restarting Apache**.
5. If the setting is missing, duplicated, or set to a different value, it prepares a normalized configuration, backs up the original file, validates Apache syntax, and restarts Apache only after a real change.
6. Attempts to restore the backup if configuration validation or restart fails.
7. Prints a report describing the configuration status and the script's CVE assessment.

The script's report is a configuration assessment. It is not a vulnerability scanner and does not prove that a server is free of every vulnerability.

## CVE assessment

The script reports the following issues separately. These statements are scoped to the vendor advisory and package family described above; they must not be generalized to unrelated builds.

### CVE-2026-109618

The cited Red Hat assessment states that the vulnerable code path associated with this CVE is not present in the RHEL 7 PHP package. Therefore, the corresponding RHEL 7 package is not considered affected by that specific issue according to that advisory.

- This conclusion is vendor- and package-specific.
- Disabling session upload progress is **not** a fix for this CVE.
- Do not use this statement to classify another vendor's PHP package without checking its advisory.

### CVE-2026-109619

For the relevant RHEL 7 PHP package, Red Hat documents that disabling session upload progress removes the exposure addressed by its advisory.

The mitigation is:

```ini
session.upload_progress.enabled = Off
```

With Apache `mod_php`, this repository applies it as:

```apache
php_admin_value session.upload_progress.enabled 0
```

This disables the feature involved in the reported attack path; it does not patch PHP source code or replace a vendor security update.

### CVE-2026-115560

The cited vendor guidance recommends disabling session upload progress as a mitigation for this issue. The Apache directive above enforces that setting for the applicable `mod_php` configuration.

Confirm the advisory for your exact distribution and package version before relying on this assessment.

## Automated installation

Review `test.sh` before executing it.

```bash
chmod 750 test.sh
sudo ./test.sh
```

Run it as `root` if `sudo` is unavailable.

Expected behavior when the setting is already configured exactly once:

```text
[OK] Mitigation is already configured exactly once.
Syntax OK
[OK] Apache configuration syntax is valid.
[INFO] No backup created; no file changed; no restart performed.
```

If a change is needed, the script creates a timestamped backup beside the configuration file, tests Apache configuration, and restarts Apache only after the configuration test passes.

After running the script, verify the effective value through the web PHP runtime as described below.

## Manual configuration

These instructions are for administrators who do not want to run the script. The exact Apache configuration path and PHP SAPI differ across distributions.

### 1. Identify the PHP SAPI and configuration

For command-line PHP:

```bash
php --ini
php -i | grep -i 'Server API'
php -i | grep -i 'session.upload_progress.enabled'
```

For Apache, inspect its loaded modules and configuration:

```bash
httpd -M 2>/dev/null | grep -E 'php.*module|mpm_'
apachectl -M 2>/dev/null | grep -E 'php.*module|mpm_'
```

On Debian/Ubuntu, the commands may be `apache2ctl -M` and the service is normally `apache2`. The PHP SAPI may be PHP-FPM rather than `mod_php`.

**The CLI value does not necessarily equal the web PHP value.** Verify the web runtime separately.

### 2. Back up the relevant configuration

For an EL7-style Apache `mod_php` setup:

```bash
sudo cp -a /etc/httpd/conf.d/php.conf \
  "/etc/httpd/conf.d/php.conf.bak.$(date +%Y%m%d-%H%M%S)"
```

On Debian/Ubuntu, the relevant configuration may be under `/etc/apache2/` and the PHP version-specific configuration directory. Do not copy the EL7 path blindly.

### 3. Add the directive

For Apache `mod_php`, add the following directive in the appropriate server or PHP configuration context:

```apache
php_admin_value session.upload_progress.enabled 0
```

On a typical EL7 `mod_php` installation, this can be placed in `/etc/httpd/conf.d/php.conf`.

Avoid adding a duplicate active directive. Search first:

```bash
grep -RniE '^[[:space:]]*php_admin_value[[:space:]]+session\.upload_progress\.enabled' \
  /etc/httpd 2>/dev/null
```

The `php_admin_value` directive is an Apache `mod_php` configuration directive. It is not valid in a PHP-FPM pool file and must not be copied there.

### 4. Alternative: set the PHP INI option

If the PHP SAPI and deployment support it, set this in the active `php.ini` or an appropriate SAPI-specific INI file:

```ini
session.upload_progress.enabled = Off
```

For PHP-FPM, use the correct FPM configuration mechanism for the installed PHP version, then reload or restart the relevant FPM service. A PHP-FPM pool does not accept Apache's `php_admin_value` syntax.

Do not assume the CLI `php.ini` is the same file used by Apache or FPM.

### 5. Validate and reload

For EL7-style Apache:

```bash
sudo httpd -t
sudo systemctl reload httpd
```

If a reload is unsupported or does not apply the change, use a planned restart:

```bash
sudo systemctl restart httpd
```

For Debian/Ubuntu, validate and reload the appropriate Apache service:

```bash
sudo apache2ctl configtest
sudo systemctl reload apache2
```

For PHP-FPM, validate and reload/restart the actual FPM service as required by the distribution. Confirm the service name first; it often includes the PHP version.

Do not restart a service until its configuration test succeeds.

## Verification

### Check the configured directive

For the EL7 Apache configuration:

```bash
grep -nE '^[[:space:]]*php_admin_value[[:space:]]+session\.upload_progress\.enabled' \
  /etc/httpd/conf.d/php.conf
```

For the `mod_php` directive, the desired active line is:

```apache
php_admin_value session.upload_progress.enabled 0
```

### Verify the effective web PHP value

The most important check is the value reported by the actual web PHP runtime. If you create a temporary PHP diagnostic file, restrict access to localhost or an administrator-only source, request it locally, and **delete it immediately afterward**.

Example diagnostic file contents:

```php
<?php
header('Content-Type: text/plain; charset=utf-8');
echo 'session.upload_progress.enabled=';
var_export(ini_get('session.upload_progress.enabled'));
echo PHP_EOL;
```

Save it temporarily in the correct web document root under a hard-to-guess temporary filename, restrict access at the web server or filesystem level, and request it locally. The expected value is `false`, `''`, or a representation of `0`/`Off`, depending on PHP version and how the value is returned.

Remove the diagnostic file immediately after verification. Never leave a public `phpinfo()` page or diagnostic endpoint exposed.

### Check service status and logs

EL7:

```bash
sudo systemctl status httpd --no-pager
sudo journalctl -u httpd -n 100 --no-pager
```

Debian/Ubuntu:

```bash
sudo systemctl status apache2 --no-pager
sudo journalctl -u apache2 -n 100 --no-pager
```

A successful configuration test does not prove that the effective setting is correct for every virtual host or SAPI.

## Rollback

If the change causes problems, restore the backup you created. Use the exact backup path printed by your command or script.

Example for EL7:

```bash
sudo cp -a /etc/httpd/conf.d/php.conf.bak.YYYYMMDD-HHMMSS \
  /etc/httpd/conf.d/php.conf
sudo httpd -t
sudo systemctl restart httpd
```

Replace `YYYYMMDD-HHMMSS` with the actual timestamp. Do not copy the example filename literally.

For other distributions, restore the correct configuration file and use that distribution's configuration test and service name.

## Additional PHP hardening

The primary mitigation in this repository is disabling session upload progress. The following settings may reduce unnecessary exposure or resource consumption, but **they are not substitutes for patching and are not fixes for the CVEs listed above**.

Review the application before changing these values. Upload limits and execution settings can affect legitimate workloads.

### Disable PHP version disclosure

In the active `php.ini`:

```ini
expose_php = Off
```

This reduces PHP version disclosure in HTTP response headers. It does not patch vulnerabilities.

### Set reasonable upload and request limits

Review these options against actual application requirements:

```ini
file_uploads = On
upload_max_filesize = 50M
post_max_size = 55M
max_file_uploads = 20
max_input_time = 60
max_execution_time = 60
memory_limit = 256M
```

These are **illustrative starting points only**, not universal recommended values. Choose limits based on application needs, available memory, request sizes, and workload. `post_max_size` should be at least as large as `upload_max_filesize` if uploads are required.

Avoid unlimited or excessively large values such as `memory_limit = -1`, `max_execution_time = 0`, or multi-gigabyte upload limits unless there is a documented operational requirement and resource controls are in place.

### Session settings

Review the session settings for the installed PHP version and application:

```ini
session.use_strict_mode = 1
session.use_only_cookies = 1
session.cookie_httponly = 1
```

Cookie security flags such as `session.cookie_secure = 1` should be enabled when the application is served exclusively over HTTPS and the deployment supports that configuration. Test application compatibility before applying session changes globally.

Do not blindly copy all settings into production. PHP versions differ in supported directives and defaults; validate the configuration after each change.

## Systems other than RHEL-compatible EL7

The provided script intentionally targets the EL7 PHP/Apache package family and may skip other systems. This is deliberate: CVE applicability and package fixes are vendor-specific.

For other operating systems:

1. Identify the exact PHP version, package release, and SAPI (Apache `mod_php`, PHP-FPM, or another handler).
2. Read the security advisory from the operating-system/vendor maintainer for the exact package.
3. Prefer the vendor's patched package or a supported PHP release.
4. If the advisory recommends disabling session upload progress, configure `session.upload_progress.enabled = Off` in the configuration used by the active web SAPI.
5. For Apache `mod_php`, `php_admin_value session.upload_progress.enabled 0` can enforce the value in the appropriate Apache configuration context.
6. For PHP-FPM, configure the setting using the supported FPM/PHP INI mechanism; do not put Apache-only directives into FPM configuration.
7. Validate the configuration, reload the correct service, and verify the effective value through the web runtime.
8. Do not mark a CVE as “not affected” solely because the version number looks similar. Check the vendor's package-specific advisory, including backported fixes.

## Troubleshooting

### The script reports that the OS is unsupported

The script is intentionally conservative. Confirm:

```bash
cat /etc/os-release
cat /etc/centos-release 2>/dev/null
rpm -q php httpd 2>/dev/null
```

Do not force the script to run on an unrelated system without reviewing its assumptions and adapting its paths, package checks, SAPI handling, and service commands.

### Apache reports `Syntax OK`, but the web setting is not disabled

Possible causes include:

- The web application uses PHP-FPM rather than `mod_php`.
- The setting was added to the wrong configuration file.
- A different Apache instance or configuration tree serves the application.
- The request reaches a different host/container.
- The value has not been reloaded into the running PHP SAPI.

Verify the active SAPI, configuration paths, service, virtual host, and effective web value.

### Apache warns that a module is already loaded

A message such as `module php5_module is already loaded, skipping` indicates a duplicate module load declaration. It is not the same as a configuration syntax failure. Investigate the duplicate `LoadModule` declarations separately and carefully; do not remove module-loading lines without confirming which configuration file is authoritative.

## References

- Red Hat Security Advisory: https://access.redhat.com/security/vulnerabilities/RHSB-2026-013
- PHP documentation: https://www.php.net/manual/en/session.upload-progress.php
- PHP configuration directives: https://www.php.net/manual/en/ini.list.php
- Apache HTTP Server documentation: https://httpd.apache.org/docs/2.4/

Always re-check the current vendor advisory before deploying this mitigation to another package family.
