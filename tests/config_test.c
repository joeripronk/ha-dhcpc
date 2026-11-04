/* Config merge test: the shared document plus the per-node overlay, overlay
 * wins (plan §6), and the digest we sync on is the shared file's bytes only. */
#define _GNU_SOURCE

#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "ha-dhcpc/config.h"

static char dir[256], base[300], local[300];
static int failures;

static void fail(const char *what)
{
    printf("config_test: FAIL (%s)\n", what);
    failures++;
}

static void ok(const char *what)
{
    printf("config_test: ok (%s)\n", what);
}

static void write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        printf("config_test: cannot write %s\n", path);
        exit(1);
    }
    fputs(text, f);
    fclose(f);
}

static const char *BASE_NOMAC = "self: node-a\n"
                                "priority: 100\n"
                                "designated_master: node-a\n"
                                "master_mac: \"aa:bb:cc:dd:ee:ff\"\n"
                                "members:\n"
                                "  - { id: node-a, sync_address: 10.10.0.1, priority: 100 }\n"
                                "  - { id: node-b, sync_address: 10.10.0.2, priority: 90 }\n"
                                "interface: eth0\n"
                                "cluster:\n"
                                "  port: 4227\n"
                                "  heartbeat_ms: 2000\n"
                                "default_role: slave\n"
                                "dhcp:\n"
                                "  rate_limit_ms: 10000\n"
                                "  request_options: [1, 3, 6]\n"
                                "ctl_socket: /run/ha-dhcpc.ctl\n";

static const char *OVERLAY = "self: node-b\n"
                             "priority: 90\n"
                             "interface: eth1\n"
                             "default_role: master\n"
                             "cluster:\n"
                             "  heartbeat_ms: 5000\n"
                             "dhcp:\n"
                             "  request_options: [1, 3, 6, 121]\n";

int main(void)
{
    hadc_conf_t conf;
    char err[512];

    snprintf(dir, sizeof(dir), "/tmp/opencode/config_test_%d", (int)getpid());
    mkdir("/tmp/opencode", 0755);
    mkdir(dir, 0755);
    snprintf(base, sizeof(base), "%s/base.conf", dir);
    snprintf(local, sizeof(local), "%s/local.conf", dir);

    /* overlay wins on every key it repeats; the rest of the shared document
     * still applies; nested mappings merge; arrays are replaced wholesale */
    write_file(base, BASE_NOMAC);
    write_file(local, OVERLAY);
    if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
        printf("config_test: %s\n", err);
        return 1;
    }
    if (strcmp(conf.self, "node-b") != 0 || conf.priority != 90)
        fail("self/priority from the overlay");
    else if (strcmp(conf.interface, "eth1") != 0 || !conf.default_role_master)
        fail("interface/default_role overrides");
    else if (conf.cluster.heartbeat_ms != 5000 || conf.cluster.port != 4227)
        fail("nested merge (overlay + untouched base key)");
    else if (conf.dhcp.n_request_options != 4 || conf.dhcp.rate_limit_ms != 10000)
        fail("array replaced wholesale + untouched dhcp key");
    else if (conf.n_members != 2 || strcmp(conf.members[1].id, "node-b") != 0)
        fail("members from the shared document");
    else if (strcmp(conf.ctl_socket, "/run/ha-dhcpc.ctl") != 0)
        fail("ctl_socket from the shared document");
    else
        ok("overlay wins, shared document applies");

    /* the synced digest is the shared file's bytes: the overlay never changes
     * it, and a change to the shared file always does */
    char sha_before[65];
    snprintf(sha_before, sizeof(sha_before), "%s", conf.sha256);
    write_file(local, "self: node-c\npriority: 10\n");
    if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
        printf("config_test: %s\n", err);
        return 1;
    }
    if (strcmp(conf.sha256, sha_before) != 0)
        fail("digest changed when only the overlay changed");
    else if (strcmp(conf.self, "node-c") != 0)
        fail("new overlay applied");
    else
        ok("digest is the shared document only");

    char bumped[2048];
    snprintf(bumped, sizeof(bumped), "%s  # a comment changes the bytes, so the digest\n",
             BASE_NOMAC);
    write_file(base, bumped);
    if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
        printf("config_test: %s\n", err);
        return 1;
    }
    if (strcmp(conf.sha256, sha_before) == 0)
        fail("digest did not change when the shared file changed");
    else
        ok("digest follows the shared file's bytes");

    /* atomic write + verify: the digest on disk must match what we wrote */
    char sha2[65];
    hadc_config_sha256_bytes(BASE_NOMAC, strlen(BASE_NOMAC), sha2);
    if (hadc_config_write_text(base, BASE_NOMAC, sha2, err, sizeof(err)) != 0) {
        printf("config_test: %s\n", err);
        return 1;
    }
    if (hadc_config_load(base, "", &conf, err, sizeof(err)) != 0) {
        printf("config_test: %s\n", err);
        return 1;
    }
    if (strcmp(conf.sha256, sha2) != 0)
        fail("written file does not digest to the text written");
    else
        ok("atomic write verified");

    if (hadc_config_write_text(base, BASE_NOMAC,
                               "0000000000000000000000000000000000000000000000000000000000000000",
                               err, sizeof(err)) == 0)
        fail("digest mismatch should refuse the write");
    else
        ok("digest mismatch refused");

    /* required keys: self must come from somewhere */
    write_file(base, "master_mac: \"aa:bb:cc:dd:ee:ff\"\ndesignated_master: node-a\ninterface: eth0\n");
    unlink(local);
    if (hadc_config_load(base, local, &conf, err, sizeof(err)) == 0)
        fail("missing self should be an error");
    else
        ok("missing self is an error");

    /* lease_file: relative resolves against the shared config's directory,
     * absolute is used as given, unset keeps the compiled-in default */
    char want[600];
    char with_lf[2048];
    snprintf(with_lf, sizeof(with_lf), "%slease_file: leases.db\n", BASE_NOMAC);
    write_file(base, with_lf);
    if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
        printf("config_test: %s\n", err);
        return 1;
    }
    snprintf(want, sizeof(want), "%s/leases.db", dir);
    if (strcmp(conf.lease_file, want) != 0)
        fail("relative lease_file resolves against the shared config dir");
    else
        ok("relative lease_file resolves against the shared config dir");

    snprintf(with_lf, sizeof(with_lf), "%slease_file: /var/lib/ha-dhcpc/leases.db\n", BASE_NOMAC);
    write_file(base, with_lf);
    if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
        printf("config_test: %s\n", err);
        return 1;
    }
    if (strcmp(conf.lease_file, "/var/lib/ha-dhcpc/leases.db") != 0)
        fail("absolute lease_file used as given");
    else
        ok("absolute lease_file used as given");

    write_file(base, BASE_NOMAC);
    if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
        printf("config_test: %s\n", err);
        return 1;
    }
    if (strcmp(conf.lease_file, "/var/lib/ha-dhcpc/dhclient.leases.eth0") != 0)
        fail("unset lease_file keeps the default");
    else
        ok("unset lease_file keeps the default");

    /* lease_file: none/off/~ opt out of the file entirely */
    const char *off_forms[] = {"none", "off", "~"};
    for (int i = 0; i < 3; i++) {
        snprintf(with_lf, sizeof(with_lf), "%slease_file: %s\n", BASE_NOMAC, off_forms[i]);
        write_file(base, with_lf);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
            printf("config_test: %s\n", err);
            return 1;
        }
        if (conf.lease_file[0] != '\0')
            fail("lease_file none/off/~ should opt out");
        else
            ok("lease_file none/off/~ opts out");
    }

    /* ddclient: parsed from the shared document, overlay wins, unset is empty */
    {
        char with_dc[2048];
        snprintf(with_dc, sizeof(with_dc), "%sapply:\n  ddclient: /usr/bin/ddclient\n", BASE_NOMAC);
        write_file(base, with_dc);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
            printf("config_test: %s\n", err);
            return 1;
        }
        if (strcmp(conf.apply.ddclient, "/usr/bin/ddclient") != 0)
            fail("ddclient parsed from the shared document");
        else
            ok("ddclient parsed from the shared document");
    }
    {
        char with_dc[2048];
        snprintf(with_dc, sizeof(with_dc), "%sapply:\n  ddclient: /usr/local/bin/dc\n", BASE_NOMAC);
        write_file(base, with_dc);
        write_file(local, "apply:\n  ddclient: /usr/bin/ddclient\n");
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
            printf("config_test: %s\n", err);
            return 1;
        }
        if (strcmp(conf.apply.ddclient, "/usr/bin/ddclient") != 0)
            fail("ddclient overlay wins");
        else
            ok("ddclient overlay wins");
        write_file(local, "self: node-b\npriority: 90\n");
    }
    {
        write_file(base, BASE_NOMAC);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
            printf("config_test: %s\n", err);
            return 1;
        }
        if (conf.apply.ddclient[0] != '\0')
            fail("unset ddclient is off");
        else
            ok("unset ddclient is off");
    }

    unlink(base);
    unlink(local);
    rmdir(dir);
    if (failures)
        return 1;
    printf("config_test: OK\n");
    return 0;
}
