/* Config merge test: the shared document plus the per-node overlay, overlay
 * wins (plan §6), and the digest we sync on is the shared file's bytes only. */

#include <arpa/inet.h>
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
        fail("self from the overlay, priority from the members list");
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
    write_file(local, "self: node-c\n");
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

    /* self defaults to the hostname when set in neither file */
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    write_file(base, "master_mac: \"aa:bb:cc:dd:ee:ff\"\ndesignated_master: node-a\ninterface: eth0\n");
    unlink(local);
    if (strlen(hostname) >= 64)
        ok("self hostname default skipped (hostname too long)");
    else if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
        fail("missing self should default to the hostname");
    else if (strcmp(conf.self, hostname) != 0)
        fail("self should default to the hostname");
    else
        ok("self defaults to the hostname");

    /* loglevel: defaults to info, parses, rejects unknown values */
    write_file(base, BASE_NOMAC);
    unlink(local);
    if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
        fail("loglevel default load");
    else if (conf.loglevel != HADC_LOG_INFO)
        fail("loglevel should default to info");
    else
        ok("loglevel defaults to info");
    char llbuf[2048];
    snprintf(llbuf, sizeof(llbuf), "%sloglevel: debug\n", BASE_NOMAC);
    write_file(base, llbuf);
    if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
        fail("loglevel parse");
    else if (conf.loglevel != HADC_LOG_DEBUG)
        fail("loglevel debug");
    else
        ok("loglevel debug parsed");
    snprintf(llbuf, sizeof(llbuf), "%sloglevel: trace\n", BASE_NOMAC);
    write_file(base, llbuf);
    if (hadc_config_load(base, local, &conf, err, sizeof(err)) == 0)
        fail("unknown loglevel should be an error");
    else
        ok("unknown loglevel rejected");

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
        write_file(local, "self: node-b\n");
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

    /* backup_gateway: parsed from apply, overlay wins, unset is off, bad
     * values are refused */
    {
        struct in_addr want_gw;
        char with_bg[2048];
        inet_pton(AF_INET, "192.168.10.1", &want_gw);

        snprintf(with_bg, sizeof(with_bg),
                 "%sapply:\n  backup_gateway: 192.168.10.1\n", BASE_NOMAC);
        write_file(base, with_bg);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("backup_gateway parse");
        else if (conf.apply.backup_gateway.s_addr != want_gw.s_addr)
            fail("backup_gateway parsed from the shared document");
        else
            ok("backup_gateway parsed from the shared document");

        write_file(base, BASE_NOMAC);
        write_file(local,
                   "self: node-b\napply:\n  backup_gateway: 192.168.10.1\n");
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("backup_gateway overlay load");
        else if (conf.apply.backup_gateway.s_addr != want_gw.s_addr)
            fail("backup_gateway overlay wins");
        else
            ok("backup_gateway overlay wins");
        write_file(local, "self: node-b\n");

        write_file(base, BASE_NOMAC);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("unset backup_gateway load");
        else if (conf.apply.backup_gateway.s_addr != 0)
            fail("unset backup_gateway is off");
        else
            ok("unset backup_gateway is off");

        const char *off_forms[] = {"none", "off", "~"};
        for (int i = 0; i < 3; i++) {
            snprintf(with_bg, sizeof(with_bg),
                     "%sapply:\n  backup_gateway: %s\n", BASE_NOMAC, off_forms[i]);
            write_file(base, with_bg);
            if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
                fail("backup_gateway off form load");
            else if (conf.apply.backup_gateway.s_addr != 0)
                fail("backup_gateway none/off/~ should be off");
            else
                ok("backup_gateway none/off/~ is off");
        }

        snprintf(with_bg, sizeof(with_bg),
                 "%sapply:\n  backup_gateway: not-an-address\n", BASE_NOMAC);
        write_file(base, with_bg);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) == 0)
            fail("bad backup_gateway should be an error");
        else
            ok("bad backup_gateway rejected");
    }

    /* master_backup_gateway: parsed from apply, overlay wins, unset is off,
     * bad values are refused */
    {
        struct in_addr want_gw;
        char with_bg[2048];
        inet_pton(AF_INET, "192.168.10.3", &want_gw);

        snprintf(with_bg, sizeof(with_bg),
                 "%sapply:\n  master_backup_gateway: 192.168.10.3\n", BASE_NOMAC);
        write_file(base, with_bg);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("master_backup_gateway parse");
        else if (conf.apply.master_backup_gateway.s_addr != want_gw.s_addr)
            fail("master_backup_gateway parsed from the shared document");
        else
            ok("master_backup_gateway parsed from the shared document");

        write_file(base, BASE_NOMAC);
        write_file(local,
                   "self: node-b\napply:\n  master_backup_gateway: 192.168.10.3\n");
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("master_backup_gateway overlay load");
        else if (conf.apply.master_backup_gateway.s_addr != want_gw.s_addr)
            fail("master_backup_gateway overlay wins");
        else
            ok("master_backup_gateway overlay wins");
        write_file(local, "self: node-b\n");

        write_file(base, BASE_NOMAC);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("unset master_backup_gateway load");
        else if (conf.apply.master_backup_gateway.s_addr != 0)
            fail("unset master_backup_gateway is off");
        else
            ok("unset master_backup_gateway is off");

        const char *off_forms[] = {"none", "off", "~"};
        for (int i = 0; i < 3; i++) {
            snprintf(with_bg, sizeof(with_bg),
                     "%sapply:\n  master_backup_gateway: %s\n", BASE_NOMAC, off_forms[i]);
            write_file(base, with_bg);
            if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
                fail("master_backup_gateway off form load");
            else if (conf.apply.master_backup_gateway.s_addr != 0)
                fail("master_backup_gateway none/off/~ should be off");
            else
                ok("master_backup_gateway none/off/~ is off");
        }

        snprintf(with_bg, sizeof(with_bg),
                 "%sapply:\n  master_backup_gateway: not-an-address\n", BASE_NOMAC);
        write_file(base, with_bg);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) == 0)
            fail("bad master_backup_gateway should be an error");
        else
            ok("bad master_backup_gateway rejected");
    }

    /* slave_isolation: defaults off, parses modes */
    {
        char with_sld[2048];

        write_file(base, BASE_NOMAC);
        unlink(local);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("slave_isolation default load");
        else if (conf.apply.slave_isolation != HADC_SLAVE_ISO_NONE)
            fail("slave_isolation default is off");
        else
            ok("slave_isolation default is off");

        snprintf(with_sld, sizeof(with_sld), "%sapply:\n  slave_isolation: down\n", BASE_NOMAC);
        write_file(base, with_sld);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("slave_isolation down parse");
        else if (conf.apply.slave_isolation != HADC_SLAVE_ISO_DOWN)
            fail("slave_isolation down parsed");
        else
            ok("slave_isolation down parsed");

        snprintf(with_sld, sizeof(with_sld), "%sapply:\n  slave_isolation: nft\n", BASE_NOMAC);
        write_file(base, with_sld);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("slave_isolation nft parse");
        else if (conf.apply.slave_isolation != HADC_SLAVE_ISO_NFT_EGRESS)
            fail("slave_isolation nft parsed");
        else
            ok("slave_isolation nft parsed");
    }

    /* abort_tcp_on_newip: defaults off, parses, overlay wins */
    {
        char with_ab[2048];

        write_file(base, BASE_NOMAC);
        unlink(local);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("abort_tcp_on_newip default load");
        else if (conf.apply.abort_tcp_on_newip)
            fail("abort_tcp_on_newip default is off");
        else
            ok("abort_tcp_on_newip default is off");

        snprintf(with_ab, sizeof(with_ab), "%sapply:\n  abort_tcp_on_newip: true\n", BASE_NOMAC);
        write_file(base, with_ab);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("abort_tcp_on_newip parse");
        else if (!conf.apply.abort_tcp_on_newip)
            fail("abort_tcp_on_newip parsed from the shared document");
        else
            ok("abort_tcp_on_newip parsed from the shared document");

        write_file(base, BASE_NOMAC);
        write_file(local, "self: node-b\napply:\n  abort_tcp_on_newip: true\n");
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("abort_tcp_on_newip overlay load");
        else if (!conf.apply.abort_tcp_on_newip)
            fail("abort_tcp_on_newip overlay wins");
        else
            ok("abort_tcp_on_newip overlay wins");
        write_file(local, "self: node-b\n");
    }

    /* apply.demote_nat_bypass_mark: default off, parses, range guard;
     * apply.demote_notrack: default on, parses */
    {
        char cbuf[2048];
        write_file(base, BASE_NOMAC);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("demote_nat_bypass_mark default load");
        else if (conf.apply.demote_nat_bypass_mark != 0)
            fail("demote_nat_bypass_mark default is off");
        else if (!conf.apply.demote_notrack)
            fail("demote_notrack default is on");
        else
            ok("demote_nat_bypass_mark default is off; demote_notrack default is on");

        snprintf(cbuf, sizeof(cbuf), "%sapply:\n  demote_nat_bypass_mark: 11781\n  demote_notrack: false\n", BASE_NOMAC);
        write_file(base, cbuf);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("demote_nat_bypass_mark parse");
        else if (conf.apply.demote_nat_bypass_mark != 11781)
            fail("demote_nat_bypass_mark parsed");
        else if (conf.apply.demote_notrack)
            fail("demote_notrack parsed false");
        else
            ok("demote_nat_bypass_mark parsed; demote_notrack parsed false");

        snprintf(cbuf, sizeof(cbuf), "%sapply:\n  demote_nat_bypass_mark: 16777216\n", BASE_NOMAC);
        write_file(base, cbuf);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) == 0)
            fail("demote_nat_bypass_mark out of range refused");
        else
            ok("demote_nat_bypass_mark out of range refused");
    }

    /* cluster: quorum defaults to majority; priority comes from the members list */
    write_file(base, BASE_NOMAC);
    unlink(local);
    if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
        fail("cluster defaults load");
    else if (conf.cluster.quorum != HADC_QUORUM_MAJORITY || conf.cluster.n_ifaces != 0)
        fail("cluster defaults (majority, no addresses)");
    else if (!conf.cluster.preempt)
        fail("cluster default: preempt on");
    else if (conf.cluster.self_demote_gap_ms != 0)
        fail("cluster default: self_demote_gap_ms off");
    else
        ok("cluster defaults: majority, no addresses, preempt on");

    /* cluster.self_demote_gap_ms: explicit parse and range guard */
    {
        char cbuf[2048];
        snprintf(cbuf, sizeof(cbuf), "%scluster:\n  self_demote_gap_ms: 250\n", BASE_NOMAC);
        write_file(base, cbuf);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
            printf("config_test: %s\n", err);
            fail("cluster self_demote_gap_ms load");
        } else if (conf.cluster.self_demote_gap_ms != 250)
            fail("cluster self_demote_gap_ms parsed");
        else
            ok("cluster self_demote_gap_ms parsed");
        snprintf(cbuf, sizeof(cbuf), "%scluster:\n  self_demote_gap_ms: 60001\n", BASE_NOMAC);
        write_file(base, cbuf);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) == 0)
            fail("cluster self_demote_gap_ms out of range refused");
        else
            ok("cluster self_demote_gap_ms out of range refused");
    }

    /* cluster.preempt: explicit false parses; non-boolean is refused */
    {
        char cbuf[2048];
        snprintf(cbuf, sizeof(cbuf), "%scluster:\n  preempt: false\n", BASE_NOMAC);
        write_file(base, cbuf);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
            printf("config_test: %s\n", err);
            fail("cluster preempt=false load");
        } else if (conf.cluster.preempt) {
            fail("cluster preempt=false parsed");
        } else {
            ok("cluster preempt=false parsed");
        }
        snprintf(cbuf, sizeof(cbuf), "%scluster:\n  preempt: sometimes\n", BASE_NOMAC);
        write_file(base, cbuf);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) == 0)
            fail("cluster preempt non-boolean refused");
        else
            ok("cluster preempt non-boolean refused");
    }

    {
        char cbuf[4096];
        snprintf(cbuf, sizeof(cbuf),
                 "%s"
                 "cluster:\n"
                 "  quorum: none\n"
                 "  addresses:\n"
                 "    br-lan:\n"
                 "      - 192.168.10.1/24\n"
                 "    br-guest:\n"
                 "      - 192.168.20.1/255.255.255.0\n",
                 BASE_NOMAC);
        write_file(base, cbuf);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
            printf("config_test: %s\n", err);
            fail("cluster addresses load");
        } else if (conf.cluster.quorum != HADC_QUORUM_NONE || conf.cluster.n_ifaces != 2) {
            fail("cluster quorum=none and two interfaces");
        } else if (strcmp(conf.cluster.ifaces[0].interface, "br-lan") != 0 ||
                   conf.cluster.ifaces[0].n_addrs != 1 ||
                   conf.cluster.ifaces[0].addrs[0].prefixlen != 24 ||
                   ntohl(conf.cluster.ifaces[0].addrs[0].address.s_addr) != 0xc0a80a01) {
            fail("cluster br-lan prefix form");
        } else if (strcmp(conf.cluster.ifaces[1].interface, "br-guest") != 0 ||
                   conf.cluster.ifaces[1].n_addrs != 1 ||
                   conf.cluster.ifaces[1].addrs[0].prefixlen != 24 ||
                   ntohl(conf.cluster.ifaces[1].addrs[0].address.s_addr) != 0xc0a81401) {
            fail("cluster br-guest dotted-netmask form");
        } else {
            ok("cluster addresses: two interfaces, prefix + netmask forms");
        }
    }

    const char *bad_cluster[] = {
        "  addresses:\n    br-lan:\n      - not-an-address/24\n",
        "  addresses:\n    br-lan:\n      - 192.168.10.1/33\n",
        "  addresses:\n    br-lan:\n      - 192.168.10.1/255.0.255.0\n",
        "  addresses:\n    br-lan:\n      - 192.168.10.1\n",
        "  quorum: sometimes\n",
    };
    for (size_t i = 0; i < sizeof(bad_cluster) / sizeof(bad_cluster[0]); i++) {
        char cbuf[2048];
        snprintf(cbuf, sizeof(cbuf), "%scluster:\n%s", BASE_NOMAC, bad_cluster[i]);
        write_file(base, cbuf);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) == 0)
            fail("bad cluster config should be an error");
        else
            ok("bad cluster config rejected");
    }

    /* conntrack_sync: off by default with documented defaults */
    write_file(base, BASE_NOMAC);
    unlink(local);
    if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
        fail("conntrack_sync default load");
    else if (conf.conntrack_sync.enabled || conf.conntrack_sync.port != 4501 ||
             conf.conntrack_sync.max_queue_entries != 8192 ||
             !conf.conntrack_sync.snapshot_on_connect ||
             conf.conntrack_sync.resync_interval_s != 0 ||
             !conf.conntrack_sync.filter.non_local_only ||
             !conf.conntrack_sync.filter.include_related ||
             !conf.conntrack_sync.filter.exclude_loopback ||
             conf.conntrack_sync.helpers.sip != HADC_CT_SIP_AUTO ||
             conf.conntrack_sync.helpers.cache_refresh_s != 30 ||
             conf.conntrack_sync.apply.slave_apply != HADC_CT_APPLY_STAGED ||
             conf.conntrack_sync.apply.max_entry_age_s != 300)
        fail("conntrack_sync defaults");
    else
        ok("conntrack_sync defaults");

    /* conntrack_sync: full parse and overlay precedence */
    {
        char cbuf[4096];
        snprintf(cbuf, sizeof(cbuf),
                 "%s"
                 "conntrack_sync:\n"
                 "  enabled: true\n"
                 "  port: 4510\n"
                 "  max_queue_entries: 1024\n"
                 "  snapshot_on_connect: false\n"
                 "  resync_interval_s: 60\n"
                 "  filter:\n"
                 "    families: [ipv4]\n"
                 "    non_local_only: false\n"
                 "    include_related: false\n"
                 "    exclude_loopback: false\n"
                 "  helpers:\n"
                 "    sip: require\n"
                 "    cache_refresh_s: 45\n"
                 "  apply:\n"
                 "    slave_apply: immediate\n"
                 "    max_entry_age_s: 120\n",
                 BASE_NOMAC);
        write_file(base, cbuf);
        unlink(local);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
            printf("config_test: %s\n", err);
            fail("conntrack_sync parse");
        } else if (!conf.conntrack_sync.enabled || conf.conntrack_sync.port != 4510 ||
                   conf.conntrack_sync.max_queue_entries != 1024 ||
                   conf.conntrack_sync.snapshot_on_connect ||
                   conf.conntrack_sync.resync_interval_s != 60 ||
                   conf.conntrack_sync.filter.non_local_only ||
                   conf.conntrack_sync.filter.include_related ||
                   conf.conntrack_sync.filter.exclude_loopback ||
                   conf.conntrack_sync.helpers.sip != HADC_CT_SIP_REQUIRE ||
                   conf.conntrack_sync.helpers.cache_refresh_s != 45 ||
                   conf.conntrack_sync.apply.slave_apply != HADC_CT_APPLY_IMMEDIATE ||
                   conf.conntrack_sync.apply.max_entry_age_s != 120) {
            fail("conntrack_sync parsed");
        } else {
            ok("conntrack_sync parsed");
        }

        write_file(local,
                   "self: node-b\n"
                   "conntrack_sync:\n"
                   "  enabled: false\n"
                   "  port: 4520\n"
                   "  helpers:\n"
                   "    sip: \"off\"\n"
                   "  apply:\n"
                   "    slave_apply: \"staged\"\n");
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0) {
            printf("config_test: %s\n", err);
            fail("conntrack_sync overlay load");
        } else if (conf.conntrack_sync.enabled || conf.conntrack_sync.port != 4520 ||
                   conf.conntrack_sync.helpers.sip != HADC_CT_SIP_OFF ||
                   conf.conntrack_sync.apply.slave_apply != HADC_CT_APPLY_STAGED ||
                   conf.conntrack_sync.resync_interval_s != 60 ||
                   conf.conntrack_sync.filter.non_local_only) {
            fail("conntrack_sync overlay precedence");
        } else {
            ok("conntrack_sync overlay precedence");
        }
    }

    /* conntrack_sync: invalid values rejected */
    {
        const char *bad_ct[] = {
            "conntrack_sync:\n  port: 0\n",
            "conntrack_sync:\n  max_queue_entries: 0\n",
            "conntrack_sync:\n  filter:\n    families: [ipv6]\n",
            "conntrack_sync:\n  helpers:\n    sip: \"maybe\"\n",
            "conntrack_sync:\n  apply:\n    slave_apply: \"later\"\n",
            "conntrack_sync:\n  enabled: sometimes\n",
        };
        for (size_t i = 0; i < sizeof(bad_ct) / sizeof(bad_ct[0]); i++) {
            char cbuf[2048];
            snprintf(cbuf, sizeof(cbuf), "%s%s", BASE_NOMAC, bad_ct[i]);
            write_file(base, cbuf);
            unlink(local);
            if (hadc_config_load(base, local, &conf, err, sizeof(err)) == 0)
                fail("bad conntrack_sync config should be an error");
            else
                ok("bad conntrack_sync config rejected");
        }
    }

    /* the members list is the single source of truth for priority: a node's
     * own value is the list entry for its own id, and a top-level priority
     * key is refused outright */
    {
        write_file(base, BASE_NOMAC);
        unlink(local);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("members-list priority load");
        else if (conf.priority != 100)
            fail("priority derived from own members entry");
        else
            ok("priority derived from own members entry");

        char with_prio[2048];
        snprintf(with_prio, sizeof(with_prio), "%spriority: 100\n", BASE_NOMAC);
        write_file(base, with_prio);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) == 0)
            fail("top-level priority should be refused");
        else
            ok("top-level priority refused");
    }

    /* identity check: with members, self must be one of them and that entry's
     * sync_address must be an address on this host; a memberless node passes */
    {
        hadc_conf_t ic;
        memset(&ic, 0, sizeof(ic));
        if (hadc_config_identity_check(&ic, err, sizeof(err)) != 0)
            fail("memberless standalone should pass the identity check");
        else
            ok("memberless standalone passes the identity check");

        snprintf(ic.self, sizeof(ic.self), "node-z");
        ic.n_members = 1;
        snprintf(ic.members[0].id, sizeof(ic.members[0].id), "node-a");
        inet_pton(AF_INET, "127.0.0.1", &ic.members[0].sync_address);
        if (hadc_config_identity_check(&ic, err, sizeof(err)) == 0)
            fail("self outside the members list should be refused");
        else
            ok("self outside the members list refused");

        snprintf(ic.self, sizeof(ic.self), "node-a");
        inet_pton(AF_INET, "10.10.0.1", &ic.members[0].sync_address);
        if (hadc_config_identity_check(&ic, err, sizeof(err)) == 0)
            fail("non-local sync_address should be refused");
        else
            ok("non-local sync_address refused");

        inet_pton(AF_INET, "127.0.0.1", &ic.members[0].sync_address);
        if (hadc_config_identity_check(&ic, err, sizeof(err)) != 0)
            fail("local sync_address should pass");
        else
            ok("identity check passes for this host's own entry");
    }

    /* ospf.announce_death: default auto (on in a cluster, off standalone);
     * explicit true/false override; auto restores the default */
    {
        char abuf[1024];
        snprintf(abuf, sizeof(abuf), "%sospf:\n  announce_death: true\n", BASE_NOMAC);
        write_file(base, abuf);
        unlink(local);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("ospf.announce_death true load");
        else if (conf.ospf.announce_death != 1)
            fail("ospf.announce_death true parsed wrong");
        else
            ok("ospf.announce_death true parsed");

        snprintf(abuf, sizeof(abuf), "%sospf:\n  announce_death: false\n", BASE_NOMAC);
        write_file(base, abuf);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("ospf.announce_death false load");
        else if (conf.ospf.announce_death != 0)
            fail("ospf.announce_death false parsed wrong");
        else
            ok("ospf.announce_death false parsed");

        write_file(base, BASE_NOMAC);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("ospf.announce_death default load");
        else if (conf.ospf.announce_death != -1)
            fail("ospf.announce_death should default to auto");
        else
            ok("ospf.announce_death defaults to auto");

        snprintf(abuf, sizeof(abuf), "%sospf:\n  announce_death: auto\n", BASE_NOMAC);
        write_file(base, abuf);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) != 0)
            fail("ospf.announce_death auto load");
        else if (conf.ospf.announce_death != -1)
            fail("ospf.announce_death auto parsed wrong");
        else
            ok("ospf.announce_death auto parsed");

        snprintf(abuf, sizeof(abuf), "%sospf:\n  announce_death: sometimes\n", BASE_NOMAC);
        write_file(base, abuf);
        if (hadc_config_load(base, local, &conf, err, sizeof(err)) == 0)
            fail("ospf.announce_death garbage should be refused");
        else
            ok("ospf.announce_death garbage refused");
    }

    unlink(base);
    unlink(local);
    rmdir(dir);
    if (failures)
        return 1;
    printf("config_test: OK\n");
    return 0;
}
