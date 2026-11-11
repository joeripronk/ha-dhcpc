/* Config loaders: YAML (libyaml) -> jansson -> typed structs (plan §6).
 * One schema, two files: the shared document (ha-dhcpc.conf) deep-merged with
 * the per-node local overlay (ha-dhcpc-local.conf), overlay wins. The digest we
 * carry is the digest of the shared document only — that is the value that is
 * stable cluster-wide and the value conf_sync carries (plan §6). */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <jansson.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <yaml.h>

#include "ha-dhcpc/config.h"
#include "ha-dhcpc/log.h"
#include "internal.h"

/* ---- YAML -> json_t (scalars resolved per YAML 1.1 plain-style rules) ---- */

static json_t *parse_node(yaml_document_t *doc, yaml_node_t *n);

static json_t *parse_scalar(yaml_node_t *n)
{
    yaml_scalar_style_t style = n->data.scalar.style;
    const char *s = (const char *)n->data.scalar.value;
    bool plain = (style == YAML_PLAIN_SCALAR_STYLE);

    if (plain) {
        if (!*s || !strcmp(s, "~") || !strcmp(s, "null") || !strcmp(s, "Null") ||
            !strcmp(s, "NULL"))
            return json_null();
        if (!strcmp(s, "true") || !strcmp(s, "True") || !strcmp(s, "TRUE") ||
            !strcmp(s, "yes") || !strcmp(s, "Yes") || !strcmp(s, "YES") ||
            !strcmp(s, "on") || !strcmp(s, "On") || !strcmp(s, "ON"))
            return json_true();
        if (!strcmp(s, "false") || !strcmp(s, "False") || !strcmp(s, "FALSE") ||
            !strcmp(s, "no") || !strcmp(s, "No") || !strcmp(s, "NO") ||
            !strcmp(s, "off") || !strcmp(s, "Off") || !strcmp(s, "OFF"))
            return json_false();
        char *end;
        long long iv = strtoll(s, &end, 10);
        if (*s && *end == '\0')
            return json_integer(iv);
        double dv = strtod(s, &end);
        if (*s && *end == '\0')
            return json_real(dv);
    }
    return json_string(s);
}

static json_t *parse_node(yaml_document_t *doc, yaml_node_t *n)
{
    yaml_node_pair_t *pair;
    yaml_node_item_t *item;

    switch (n->type) {
    case YAML_SCALAR_NODE:
        return parse_scalar(n);
    case YAML_SEQUENCE_NODE: {
        json_t *arr = json_array();
        for (item = n->data.sequence.items.start; item < n->data.sequence.items.top; item++) {
            yaml_node_t *child = yaml_document_get_node(doc, *item);
            json_array_append_new(arr, parse_node(doc, child));
        }
        return arr;
    }
    case YAML_MAPPING_NODE: {
        json_t *obj = json_object();
        for (pair = n->data.mapping.pairs.start; pair < n->data.mapping.pairs.top; pair++) {
            yaml_node_t *k = yaml_document_get_node(doc, pair->key);
            yaml_node_t *v = yaml_document_get_node(doc, pair->value);
            if (k->type != YAML_SCALAR_NODE)
                continue; /* non-scalar keys not used by our schema */
            json_object_set_new(obj, (const char *)k->data.scalar.value,
                                parse_node(doc, v));
        }
        return obj;
    }
    default:
        return json_null();
    }
}

json_t *hadc_config_read_yaml(const char *path, char *err, size_t errlen)
{
    yaml_parser_t parser;
    yaml_document_t doc;
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(err, errlen, "cannot open %s: %s", path, strerror(errno));
        return NULL;
    }
    if (!yaml_parser_initialize(&parser)) {
        fclose(f);
        snprintf(err, errlen, "yaml_parser_initialize failed");
        return NULL;
    }
    yaml_parser_set_input_file(&parser, f);

    json_t *out = NULL;
    if (!yaml_parser_load(&parser, &doc)) {
        snprintf(err, errlen, "YAML parse error in %s (line %zu): %s", path,
                 parser.problem_mark.line + 1,
                 parser.problem ? parser.problem : "unknown");
        goto out;
    }
    yaml_node_t *root = yaml_document_get_root_node(&doc);
    if (!root) {
        snprintf(err, errlen, "%s: empty document", path);
        yaml_document_delete(&doc);
        goto out;
    }
    if (root->type != YAML_MAPPING_NODE) {
        snprintf(err, errlen, "%s: root must be a mapping", path);
        yaml_document_delete(&doc);
        goto out;
    }
    out = parse_node(&doc, root);
    yaml_document_delete(&doc);
out:
    yaml_parser_delete(&parser);
    fclose(f);
    return out;
}

/* ---- byte reads, digests, atomic writes (the shared document travels as
 * bytes so a pushed copy keeps its comments and formatting) ---- */

int hadc_config_read_bytes(const char *path, size_t max_bytes, char **out,
                           size_t *outlen, char *err, size_t errlen)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(err, errlen, "cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        snprintf(err, errlen, "%s: seek failed: %s", path, strerror(errno));
        fclose(f);
        return -1;
    }
    long size = ftell(f);
    if (size < 0 || (size_t)size > max_bytes) {
        snprintf(err, errlen, "%s: %ld bytes exceeds the %zu-byte limit", path, size,
                 max_bytes);
        fclose(f);
        return -1;
    }
    char *buf = malloc((size_t)size + 1);
    if (!buf) {
        snprintf(err, errlen, "%s: out of memory", path);
        fclose(f);
        return -1;
    }
    rewind(f);
    if (size > 0 && fread(buf, (size_t)size, 1, f) != 1) {
        snprintf(err, errlen, "%s: read failed: %s", path, strerror(errno));
        free(buf);
        fclose(f);
        return -1;
    }
    buf[size] = '\0';
    fclose(f);
    *out = buf;
    *outlen = (size_t)size;
    return 0;
}

int hadc_config_sha256_bytes(const void *data, size_t len, char out[HADC_CONF_SHA_HEX])
{
    uint8_t digest[32];
    hadc_sha256(data, len, digest);
    for (int i = 0; i < 32; i++)
        sprintf(out + 2 * i, "%02x", digest[i]);
    out[64] = '\0';
    return 0;
}

int hadc_config_write_text(const char *path, const char *text,
                           const char sha256[HADC_CONF_SHA_HEX], char *err, size_t errlen)
{
    char tmp[HADC_PATH_MAX + 16], check[HADC_CONF_SHA_HEX];
    size_t len;
    char *bytes = NULL;
    int rc = 0;

    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        snprintf(err, errlen, "config: fopen %s: %s", tmp, strerror(errno));
        return -1;
    }
    if (fputs(text, f) == EOF)
        rc = 1;
    if (!rc && (fflush(f) != 0 || fsync(fileno(f)) != 0))
        rc = 1;
    if (fclose(f) != 0)
        rc = 1;
    if (rc) {
        snprintf(err, errlen, "config: write %s failed: %s", tmp, strerror(errno));
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        snprintf(err, errlen, "config: rename to %s: %s", path, strerror(errno));
        unlink(tmp);
        return -1;
    }

    /* verify: the file on disk must digest to what we were told it would */
    if (hadc_config_read_bytes(path, HADC_CONF_MAX_BYTES, &bytes, &len, err, errlen) != 0)
        return -1;
    if (hadc_config_sha256_bytes(bytes, len, check) != 0 || strcmp(check, sha256) != 0) {
        snprintf(err, errlen, "config: %s digest mismatch after write (wanted %s, file is %s)",
                 path, sha256, check);
        free(bytes);
        return -1;
    }
    free(bytes);
    return 0;
}

/* ---- overlay merge: overlay wins; objects recurse, all else is replaced ---- */

json_t *hadc_config_merge_json(json_t *base, json_t *overlay)
{
    if (!base)
        return overlay ? json_copy(overlay) : json_null();
    if (!overlay)
        return json_copy(base);
    if (!json_is_object(base) || !json_is_object(overlay))
        return json_copy(overlay);

    json_t *out = json_deep_copy(base);
    const char *key;
    json_t *v;
    json_object_foreach(overlay, key, v) {
        json_t *b = json_object_get(out, key);
        json_t *merged = (b && json_is_object(b) && json_is_object(v))
                             ? hadc_config_merge_json(b, v)
                             : json_copy(v);
        json_object_set_new(out, key, merged);
    }
    return out;
}

int hadc_config_digest_json(const json_t *doc, char out[HADC_CONF_SHA_HEX])
{
    char *txt = json_dumps(doc ? doc : json_null(), JSON_PRESERVE_ORDER | JSON_COMPACT);
    if (!txt)
        return -1;
    uint8_t digest[32];
    hadc_sha256(txt, strlen(txt), digest);
    free(txt);
    for (int i = 0; i < 32; i++)
        sprintf(out + 2 * i, "%02x", digest[i]);
    out[64] = '\0';
    return 0;
}

/* ---- schema extraction helpers ---- */

static char g_errbuf[512];

static int get_str(json_t *o, const char *key, char *dst, size_t dstsz, bool required,
                   const char *what)
{
    json_t *v = o ? json_object_get(o, key) : NULL;
    if (!v || !json_is_string(v)) {
        if (required) {
            snprintf(g_errbuf, sizeof(g_errbuf), "%s: missing %s", what, key);
            return -1;
        }
        return 0;
    }
    snprintf(dst, dstsz, "%s", json_string_value(v));
    return 0;
}

static int get_int(json_t *o, const char *key, long long *dst, long long dflt,
                   bool required, const char *what)
{
    json_t *v = o ? json_object_get(o, key) : NULL;
    if (!v || json_is_null(v)) {
        if (required) {
            snprintf(g_errbuf, sizeof(g_errbuf), "%s: missing %s", what, key);
            return -1;
        }
        *dst = dflt;
        return 0;
    }
    if (!json_is_integer(v)) {
        snprintf(g_errbuf, sizeof(g_errbuf), "%s: %s must be an integer", what, key);
        return -1;
    }
    *dst = json_integer_value(v);
    return 0;
}

static int get_bool(json_t *o, const char *key, bool *dst, bool dflt)
{
    json_t *v = o ? json_object_get(o, key) : NULL;
    if (!v || json_is_null(v)) {
        *dst = dflt;
        return 0;
    }
    if (!json_is_boolean(v)) {
        snprintf(g_errbuf, sizeof(g_errbuf), "%s: %s must be a boolean", "daemon conf", key);
        return -1;
    }
    *dst = json_is_true(v);
    return 0;
}

static int get_addr(json_t *o, const char *key, struct in_addr *dst)
{
    json_t *v = o ? json_object_get(o, key) : NULL;
    if (!v || json_is_null(v) || (json_is_boolean(v) && !json_is_true(v))) {
        dst->s_addr = 0; /* null and bare false count as "off" */
        return 0;
    }
    if (!json_is_string(v)) {
        snprintf(g_errbuf, sizeof(g_errbuf), "config: apply.%s must be an IPv4 address", key);
        return -1;
    }
    const char *s = json_string_value(v);
    dst->s_addr = 0;
    if (*s && strcmp(s, "none") && strcmp(s, "off") && strcmp(s, "no") &&
        inet_pton(AF_INET, s, dst) != 1) {
        snprintf(g_errbuf, sizeof(g_errbuf), "config: bad apply.%s %s", key, s);
        return -1;
    }
    return 0;
}

static int parse_mac(const char *s, uint8_t out[HADC_MAC_LEN])
{
    unsigned b[6];
    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        out[i] = (uint8_t)b[i];
    return 0;
}

/* IPv4 address plus either a prefix length (192.168.10.1/24) or a dotted
 * netmask (192.168.10.1/255.255.255.0). */
static int parse_cidr4(const char *s, struct in_addr *out, unsigned *prefixlen)
{
    char buf[64];
    if (!s || strlen(s) >= sizeof(buf))
        return -1;
    snprintf(buf, sizeof(buf), "%s", s);
    char *slash = strchr(buf, '/');
    if (!slash)
        return -1;
    *slash = '\0';
    if (inet_pton(AF_INET, buf, out) != 1)
        return -1;

    const char *p = slash + 1;
    if (strchr(p, '.')) {
        struct in_addr mask;
        if (inet_pton(AF_INET, p, &mask) != 1)
            return -1;
        uint32_t m = ntohl(mask.s_addr);
        uint32_t inv = ~m;
        if (inv & (inv + 1))
            return -1; /* non-contiguous netmask */
        *prefixlen = (unsigned)__builtin_popcount(m);
    } else {
        char *end;
        unsigned long v = strtoul(p, &end, 10);
        if (!*p || *end != '\0' || v > 32)
            return -1;
        *prefixlen = (unsigned)v;
    }
    return 0;
}

/* ---- merged loader (base + local overlay, overlay wins) ---- */

int hadc_config_load(const char *base_path, const char *local_path, hadc_conf_t *out,
                     char *err, size_t errlen)
{
    char err2[256];
    char *bytes = NULL;
    size_t byteslen = 0;

    /* The digest we carry is the digest of the shared file's bytes: that is the
     * unit conf_sync copies, so it must be byte-exact. */
    if (hadc_config_read_bytes(base_path, HADC_CONF_MAX_BYTES, &bytes, &byteslen, err,
                               errlen) != 0)
        return -1;

    json_t *base = hadc_config_read_yaml(base_path, err, errlen);
    if (!base) {
        free(bytes);
        return -1;
    }

    /* The local overlay is optional — a node with nothing per-node to say can
     * run on the shared document alone — but an existing file must parse. */
    json_t *local = NULL;
    if (local_path && *local_path && access(local_path, F_OK) == 0) {
        local = hadc_config_read_yaml(local_path, err2, sizeof(err2));
        if (!local) {
            snprintf(err, errlen, "%s", err2);
            json_decref(base);
            free(bytes);
            return -1;
        }
    }

    json_t *root = hadc_config_merge_json(base, local);
    if (local)
        json_decref(local);
    json_decref(base);
    if (!root) {
        free(bytes);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    long long v;

    snprintf(out->base_path, HADC_PATH_MAX, "%s", base_path);
    snprintf(out->local_path, HADC_PATH_MAX, "%s", local_path ? local_path : "");
    if (hadc_config_sha256_bytes(bytes, byteslen, out->sha256) != 0) {
        snprintf(err, errlen, "config: digest failed");
        json_decref(root);
        free(bytes);
        return -1;
    }
    free(bytes);

    /* identity: per-node (the local overlay is where these usually live);
     * defaults to the system hostname when set in neither file */
    if (get_str(root, "self", out->self, HADC_NODE_ID_MAX, false, "config")) {
        snprintf(err, errlen, "%s", g_errbuf);
        goto derr;
    }
    if (out->self[0] == '\0') {
        char host[256];
        if (gethostname(host, sizeof(host)) != 0 || host[0] == '\0' ||
            strlen(host) >= HADC_NODE_ID_MAX) {
            snprintf(err, errlen, "config: self not set and hostname unavailable");
            goto derr;
        }
        snprintf(out->self, sizeof(out->self), "%s", host);
    }
    if (get_int(root, "priority", &v, 100, false, "config"))
        goto derr;
    out->priority = (int)v;

    /* shared cluster membership */
    char mac[64];
    if (get_str(root, "designated_master", out->designated_master, HADC_NODE_ID_MAX, true,
                "config") ||
        get_str(root, "master_mac", mac, sizeof(mac), true, "config")) {
        snprintf(err, errlen, "%s", g_errbuf);
        goto derr;
    }
    snprintf(out->seed_master, sizeof(out->seed_master), "%s", out->designated_master);
    if (parse_mac(mac, out->master_mac) != 0) {
        snprintf(err, errlen, "config: bad master_mac %s", mac);
        goto derr;
    }
    json_t *members = json_object_get(root, "members");
    if (members && json_is_array(members)) {
        json_t *m;
        size_t idx;
        json_array_foreach(members, idx, m) {
            if (out->n_members >= HADC_MEMBERS_MAX) {
                snprintf(err, errlen, "config: too many members");
                goto derr;
            }
            hadc_member_t *mm = &out->members[out->n_members++];
            if (get_str(m, "id", mm->id, HADC_NODE_ID_MAX, true, "config member")) {
                snprintf(err, errlen, "%s", g_errbuf);
                goto derr;
            }
            char addr[64];
            if (get_str(m, "sync_address", addr, sizeof(addr), true, "config member") ||
                inet_pton(AF_INET, addr, &mm->sync_address) != 1) {
                snprintf(err, errlen, "config member %s: bad sync_address", mm->id);
                goto derr;
            }
            json_t *pj = json_object_get(m, "priority");
            mm->priority = (pj && json_is_integer(pj)) ? (int)json_integer_value(pj) : 0;
        }
    }

    if (get_str(root, "interface", out->interface, HADC_IFNAME_MAX, true, "config")) {
        snprintf(err, errlen, "%s", g_errbuf);
        goto derr;
    }

    const char *ll = "info";
    json_t *llv = json_object_get(root, "loglevel");
    if (llv && !json_is_string(llv)) {
        snprintf(err, errlen, "config: loglevel must be a string");
        goto derr;
    }
    if (llv)
        ll = json_string_value(llv);
    if (!strcmp(ll, "debug"))
        out->loglevel = HADC_LOG_DEBUG;
    else if (!strcmp(ll, "info"))
        out->loglevel = HADC_LOG_INFO;
    else if (!strcmp(ll, "warn"))
        out->loglevel = HADC_LOG_WARN;
    else if (!strcmp(ll, "err"))
        out->loglevel = HADC_LOG_ERR;
    else {
        snprintf(err, errlen, "config: unknown loglevel %s", ll);
        goto derr;
    }

    json_t *c = json_object_get(root, "cluster");
    if (get_int(c ? c : root, "port", &v, 4227, false, "cluster")) goto derr;
    out->cluster.port = (uint16_t)v;
    if (get_int(c ? c : root, "heartbeat_ms", &v, 2000, false, "cluster")) goto derr;
    out->cluster.heartbeat_ms = (uint32_t)v;
    if (get_int(c ? c : root, "election_deadline_ms", &v, 6000, false, "cluster")) goto derr;
    out->cluster.election_deadline_ms = (uint32_t)v;
    const char *q = "majority";
    json_t *qv = c ? json_object_get(c, "quorum") : NULL;
    if (qv && !json_is_string(qv)) {
        snprintf(err, errlen, "config: cluster.quorum must be a string");
        goto derr;
    }
    if (qv)
        q = json_string_value(qv);
    if (!strcmp(q, "majority"))
        out->cluster.quorum = HADC_QUORUM_MAJORITY;
    else if (!strcmp(q, "none"))
        out->cluster.quorum = HADC_QUORUM_NONE;
    else {
        snprintf(err, errlen, "config: unknown cluster.quorum %s", q);
        goto derr;
    }
    if (get_int(c ? c : root, "cluster_timeout_ms", &v, 0, false, "cluster")) goto derr;
    out->cluster.cluster_timeout_ms = (uint32_t)v;
    if (get_bool(c ? c : root, "preempt", &out->cluster.preempt, true)) goto derr;

    /* cluster.addresses: interface name -> list of address/prefix entries.
     * Every member loads the same list; only the master puts them on the
     * interface. */
    json_t *ca = c ? json_object_get(c, "addresses") : NULL;
    if (ca) {
        if (!json_is_object(ca)) {
            snprintf(err, errlen, "config: cluster.addresses must be a mapping");
            goto derr;
        }
        const char *ifname;
        json_t *list;
        json_object_foreach(ca, ifname, list) {
            if (!*ifname || strlen(ifname) >= HADC_IFNAME_MAX) {
                snprintf(err, errlen, "config: bad cluster.address interface '%s'", ifname);
                goto derr;
            }
            if (!json_is_array(list)) {
                snprintf(err, errlen, "config: cluster.addresses.%s must be a list", ifname);
                goto derr;
            }
            json_t *addr_list = list;
            json_t *if6 = NULL;
            if (json_is_object(list)) {
                addr_list = json_object_get(list, "addresses");
                if (!addr_list)
                    addr_list = json_object_get(list, "addrs");
                if6 = json_object_get(list, "disable_ipv6");
            }
            if (!json_is_array(addr_list)) {
                snprintf(err, errlen, "config: cluster.addresses.%s must be a list or {addresses:[...], disable_ipv6:bool}", ifname);
                goto derr;
            }
            /* The per-node overlay may replace an interface's list wholesale. */
            hadc_cluster_if_t *ci = NULL;
            for (size_t i = 0; i < out->cluster.n_ifaces; i++)
                if (!strcmp(out->cluster.ifaces[i].interface, ifname)) {
                    ci = &out->cluster.ifaces[i];
                    ci->n_addrs = 0;
                    ci->ipv6_disable_set = false;
                    break;
                }
            if (!ci) {
                if (out->cluster.n_ifaces >= HADC_CLUSTER_IF_MAX) {
                    snprintf(err, errlen, "config: too many cluster.address interfaces");
                    goto derr;
                }
                ci = &out->cluster.ifaces[out->cluster.n_ifaces++];
                snprintf(ci->interface, sizeof(ci->interface), "%s", ifname);
            }
            if (if6) {
                if (!json_is_boolean(if6)) {
                    snprintf(err, errlen, "config: cluster.addresses.%s.disable_ipv6 must be a boolean", ifname);
                    goto derr;
                }
                ci->ipv6_disable = json_is_true(if6);
                ci->ipv6_disable_set = true;
            }
            json_t *e;
            size_t idx;
            json_array_foreach(addr_list, idx, e) {
                if (ci->n_addrs >= HADC_CLUSTER_ADDR_MAX) {
                    snprintf(err, errlen, "config: too many cluster addresses on %s", ifname);
                    goto derr;
                }
                if (!json_is_string(e)) {
                    snprintf(err, errlen, "config: cluster.addresses.%s entries must be strings",
                             ifname);
                    goto derr;
                }
                hadc_cluster_addr_t *a = &ci->addrs[ci->n_addrs];
                if (parse_cidr4(json_string_value(e), &a->address, &a->prefixlen) != 0) {
                    snprintf(err, errlen, "config: bad cluster address '%s' on %s (want "
                             "address/prefix)", json_string_value(e), ifname);
                    goto derr;
                }
                ci->n_addrs++;
            }
        }
    }

    const char *dr = "slave";
    json_t *drv = json_object_get(root, "default_role");
    if (drv && json_is_string(drv))
        dr = json_string_value(drv);
    if (!strcmp(dr, "slave"))
        out->default_role_master = false;
    else if (!strcmp(dr, "master"))
        out->default_role_master = true;
    else {
        snprintf(err, errlen, "config: unknown default_role %s", dr);
        goto derr;
    }

    json_t *d = json_object_get(root, "dhcp");
    const char *ret = "forever";
    json_t *rv = d ? json_object_get(d, "retention") : NULL;
    if (rv && json_is_string(rv))
        ret = json_string_value(rv);
    if (!strcmp(ret, "forever"))
        out->dhcp.retention = HADC_RETENTION_FOREVER;
    else if (!strcmp(ret, "max_duration"))
        out->dhcp.retention = HADC_RETENTION_MAX_DURATION;
    else if (!strcmp(ret, "until_carrier_loss"))
        out->dhcp.retention = HADC_RETENTION_UNTIL_CARRIER_LOSS;
    else if (!strcmp(ret, "off"))
        out->dhcp.retention = HADC_RETENTION_OFF;
    else {
        snprintf(err, errlen, "config: unknown retention %s", ret);
        goto derr;
    }
    if (get_int(d ? d : root, "retention_max_duration_s", &v, 0, false, "dhcp")) goto derr;
    out->dhcp.retention_max_duration_s = (uint64_t)v;
    json_t *rr = d ? json_object_get(d, "rediscover_in_retention") : NULL;
    out->dhcp.rediscover_in_retention = rr && json_is_boolean(rr) ? json_is_true(rr) : true;
    if (get_int(d ? d : root, "rate_limit_ms", &v, 0, false, "dhcp")) goto derr;
    if (v < 0 || v > 3600000) {
        snprintf(err, errlen, "config: rate_limit_ms out of range 0..3600000");
        goto derr;
    }
    out->dhcp.rate_limit_ms = (uint32_t)v;
    if (get_int(d ? d : root, "renew_retry_interval_s", &v, 30, false, "dhcp")) goto derr;
    if (v < 0 || v > 86400) {
        snprintf(err, errlen, "config: renew_retry_interval_s out of range 0..86400");
        goto derr;
    }
    out->dhcp.renew_retry_interval_s = (uint32_t)v;
    json_t *ro = d ? json_object_get(d, "request_options") : NULL;
    if (ro && json_is_array(ro)) {
        json_t *e;
        size_t idx;
        json_array_foreach(ro, idx, e) {
            if (!json_is_integer(e) || json_integer_value(e) < 0 || json_integer_value(e) > 255 ||
                out->dhcp.n_request_options >= HADC_OPTS_MAX) {
                snprintf(err, errlen, "config: bad request_options entry");
                goto derr;
            }
            out->dhcp.request_options[out->dhcp.n_request_options++] =
                (uint8_t)json_integer_value(e);
        }
    }

    json_t *a = json_object_get(root, "apply");
    if (a) {
        if (get_bool(a, "routes", &out->apply.routes, true)) goto derr;
    } else {
        out->apply.routes = true;
    }
    if (get_addr(a, "backup_gateway", &out->apply.backup_gateway)) goto derr;
    if (get_addr(a, "master_backup_gateway", &out->apply.master_backup_gateway)) goto derr;
    snprintf(out->apply.dns_hook, HADC_PATH_MAX, "%s",
             (a && json_object_get(a, "dns_hook") && json_is_string(json_object_get(a, "dns_hook")))
                 ? json_string_value(json_object_get(a, "dns_hook"))
                 : "");
    snprintf(out->apply.ddclient, HADC_PATH_MAX, "%s",
             (a && json_object_get(a, "ddclient") && json_is_string(json_object_get(a, "ddclient")))
                 ? json_string_value(json_object_get(a, "ddclient"))
                 : "");
    out->apply.suppress_member_dad = true;
    out->apply.arp_responder = true;
    out->apply.announce_gratuitous = true;
    out->apply.slave_link_down = false;
    out->apply.slave_isolation = HADC_SLAVE_ISO_NONE;
    out->apply.gateway_probe = true;
    out->apply.gateway_probe_interval_ms = 10000;
    out->apply.gateway_probe_timeout_ms = 2000;
    out->apply.gateway_probe_fail_threshold = 3;
    out->apply.abort_tcp_on_newip = false;
    out->apply.disable_ipv6 = true;
    out->apply.dhcp_disable_ipv6_set = false;
    if (a) {
        if (get_bool(a, "suppress_member_dad", &out->apply.suppress_member_dad, true)) goto derr;
        if (get_bool(a, "arp_responder", &out->apply.arp_responder, true)) goto derr;
        if (get_bool(a, "announce_gratuitous", &out->apply.announce_gratuitous, true)) goto derr;
        if (get_bool(a, "slave_link_down", &out->apply.slave_link_down, false)) goto derr;
        {
            json_t *iso = json_object_get(a, "slave_isolation");
            if (iso) {
                if (!json_is_string(iso)) {
                    snprintf(err, errlen, "config: slave_isolation must be a string");
                    goto derr;
                }
                const char *s = json_string_value(iso);
                if (!strcmp(s, "none") || !strcmp(s, "off"))
                    out->apply.slave_isolation = HADC_SLAVE_ISO_NONE;
                else if (!strcmp(s, "down") || !strcmp(s, "link_down"))
                    out->apply.slave_isolation = HADC_SLAVE_ISO_DOWN;
                else if (!strcmp(s, "nft") || !strcmp(s, "nft_egress"))
                    out->apply.slave_isolation = HADC_SLAVE_ISO_NFT_EGRESS;
                else {
                    snprintf(err, errlen, "config: unknown slave_isolation %s", s);
                    goto derr;
                }
            } else if (out->apply.slave_link_down) {
                out->apply.slave_isolation = HADC_SLAVE_ISO_DOWN;
            }
        }
        out->apply.slave_link_down = (out->apply.slave_isolation == HADC_SLAVE_ISO_DOWN);
        if (get_bool(a, "gateway_probe", &out->apply.gateway_probe, true)) goto derr;
        if (get_int(a, "gateway_probe_interval_ms", &v, 10000, false, "apply")) goto derr;
        if (v < 100 || v > 3600000) {
            snprintf(err, errlen, "config: gateway_probe_interval_ms out of range 100..3600000");
            goto derr;
        }
        out->apply.gateway_probe_interval_ms = (uint32_t)v;
        if (get_int(a, "gateway_probe_timeout_ms", &v, 2000, false, "apply")) goto derr;
        if (v < 100 || v > 3600000) {
            snprintf(err, errlen, "config: gateway_probe_timeout_ms out of range 100..3600000");
            goto derr;
        }
        out->apply.gateway_probe_timeout_ms = (uint32_t)v;
        if (get_int(a, "gateway_probe_fail_threshold", &v, 3, false, "apply")) goto derr;
        if (v < 1 || v > 100) {
            snprintf(err, errlen, "config: gateway_probe_fail_threshold out of range 1..100");
            goto derr;
        }
        out->apply.gateway_probe_fail_threshold = (uint32_t)v;
        if (get_bool(a, "abort_tcp_on_newip", &out->apply.abort_tcp_on_newip, false)) goto derr;
        if (get_bool(a, "disable_ipv6", &out->apply.disable_ipv6, true)) goto derr;
        if (json_object_get(a, "disable_ipv6_dhcp")) {
            if (get_bool(a, "disable_ipv6_dhcp", &out->apply.dhcp_disable_ipv6, out->apply.disable_ipv6))
                goto derr;
            out->apply.dhcp_disable_ipv6_set = true;
        }
    }

    if (get_str(root, "ctl_socket", out->ctl_socket, HADC_PATH_MAX, false, "config")) goto derr;
    if (!out->ctl_socket[0])
        snprintf(out->ctl_socket, HADC_PATH_MAX, "/run/ha-dhcpc.ctl");

    /* routing (edge-only inter-cluster routing; off by default). */
    out->routing.enabled = false;
    out->routing.advertise.public_ip32 = HADC_ADV_PUB_MASTER;
    out->routing.advertise.vip_subnets = false;
    out->routing.advertise.default_route = false;
    out->routing.accept.default_route = false;
    snprintf(out->routing.backend, sizeof(out->routing.backend), "local");
    out->ospf.n_interfaces = 0;
    out->ospf.router_id[0] = '\0';
    out->ospf.auth.type = 0;
    out->ospf.auth.key[0] = '\0';
    out->ospf.auth.key_id = 0;
    {
        json_t *r = json_object_get(root, "routing");
        if (r) {
            if (!json_is_object(r)) {
                snprintf(err, errlen, "config: routing must be a mapping");
                goto derr;
            }
            if (get_bool(r, "enabled", &out->routing.enabled, false)) goto derr;
            json_t *rb = json_object_get(r, "backend");
            if (rb && json_is_string(rb))
                snprintf(out->routing.backend, sizeof(out->routing.backend), "%s", json_string_value(rb));
            else if (rb) {
                snprintf(err, errlen, "config: routing.backend must be a string");
                goto derr;
            }
            json_t *ra = json_object_get(r, "advertise");
            if (ra) {
                if (!json_is_object(ra)) {
                    snprintf(err, errlen, "config: routing.advertise must be a mapping");
                    goto derr;
                }
                {
                    json_t *pub = json_object_get(ra, "public_ip32");
                    if (pub) {
                        if (json_is_boolean(pub)) {
                            out->routing.advertise.public_ip32 = json_is_true(pub) ? HADC_ADV_PUB_MASTER : HADC_ADV_PUB_OFF;
                        } else if (json_is_string(pub)) {
                            const char *s = json_string_value(pub);
                            if (!strcmp(s, "always"))
                                out->routing.advertise.public_ip32 = HADC_ADV_PUB_ALWAYS;
                            else if (!strcmp(s, "on") || !strcmp(s, "true") || !strcmp(s, "master"))
                                out->routing.advertise.public_ip32 = HADC_ADV_PUB_MASTER;
                            else if (!strcmp(s, "off") || !strcmp(s, "false") || !strcmp(s, "none"))
                                out->routing.advertise.public_ip32 = HADC_ADV_PUB_OFF;
                            else {
                                snprintf(err, errlen, "config: unknown routing.advertise.public_ip32 %s", s);
                                goto derr;
                            }
                        } else {
                            snprintf(err, errlen, "config: routing.advertise.public_ip32 must be a boolean or string");
                            goto derr;
                        }
                    } else {
                        out->routing.advertise.public_ip32 = HADC_ADV_PUB_MASTER;
                    }
                }
                if (get_bool(ra, "vip_subnets", &out->routing.advertise.vip_subnets, false)) goto derr;
                if (get_bool(ra, "default_route", &out->routing.advertise.default_route, false)) goto derr;
            }
            json_t *rc = json_object_get(r, "accept");
            if (rc) {
                if (!json_is_object(rc)) {
                    snprintf(err, errlen, "config: routing.accept must be a mapping");
                    goto derr;
                }
                if (get_bool(rc, "default_route", &out->routing.accept.default_route, false)) goto derr;
            }
        }
        json_t *o = json_object_get(root, "ospf");
        if (o) {
            if (!json_is_object(o)) {
                snprintf(err, errlen, "config: ospf must be a mapping");
                goto derr;
            }
            json_t *rid = json_object_get(o, "router_id");
            if (rid && json_is_string(rid))
                snprintf(out->ospf.router_id, sizeof(out->ospf.router_id), "%s", json_string_value(rid));
            else if (rid) {
                snprintf(err, errlen, "config: ospf.router_id must be a string");
                goto derr;
            }
            json_t *ifs = json_object_get(o, "interfaces");
            if (!ifs)
                ifs = json_object_get(o, "interface");
            if (ifs && json_is_string(ifs)) {
                if (out->ospf.n_interfaces < HADC_CLUSTER_IF_MAX)
                    snprintf(out->ospf.interfaces[out->ospf.n_interfaces++], HADC_IFNAME_MAX, "%s",
                             json_string_value(ifs));
            } else if (ifs && json_is_array(ifs)) {
                json_t *e;
                size_t idx;
                json_array_foreach(ifs, idx, e) {
                    if (!json_is_string(e) || out->ospf.n_interfaces >= HADC_CLUSTER_IF_MAX) {
                        snprintf(err, errlen, "config: bad ospf.interfaces entry");
                        goto derr;
                    }
                    snprintf(out->ospf.interfaces[out->ospf.n_interfaces++], HADC_IFNAME_MAX, "%s",
                             json_string_value(e));
                }
            } else if (ifs) {
                snprintf(err, errlen, "config: ospf.interfaces must be a list or string");
                goto derr;
            }
            json_t *au = json_object_get(o, "auth");
            if (au && !json_is_null(au)) {
                if (!json_is_object(au)) {
                    snprintf(err, errlen, "config: ospf.auth must be a mapping");
                    goto derr;
                }
                const char *t = "none";
                json_t *tv = json_object_get(au, "type");
                if (tv && json_is_string(tv))
                    t = json_string_value(tv);
                if (!strcmp(t, "none") || !strcmp(t, "off"))
                    out->ospf.auth.type = 0;
                else if (!strcmp(t, "plaintext") || !strcmp(t, "simple"))
                    out->ospf.auth.type = 1;
                else if (!strcmp(t, "md5"))
                    out->ospf.auth.type = 2;
                else {
                    snprintf(err, errlen, "config: unknown ospf.auth.type %s", t);
                    goto derr;
                }
                json_t *kv = json_object_get(au, "key");
                if (kv && json_is_string(kv))
                    snprintf(out->ospf.auth.key, sizeof(out->ospf.auth.key), "%s", json_string_value(kv));
                json_t *kid = json_object_get(au, "key_id");
                if (kid && json_is_integer(kid))
                    out->ospf.auth.key_id = (int)json_integer_value(kid);
                if (out->ospf.auth.type != 0 && out->ospf.auth.key[0] == '\0') {
                    snprintf(err, errlen, "config: ospf.auth.key required for %s", t);
                    goto derr;
                }
            }
        }
        if (out->routing.enabled && out->ospf.n_interfaces == 0) {
            snprintf(err, errlen, "config: ospf.interfaces required when routing.enabled is true");
            goto derr;
        }
        if (out->ospf.router_id[0]) {
            struct in_addr rid;
            if (inet_pton(AF_INET, out->ospf.router_id, &rid) != 1 || rid.s_addr == 0) {
                snprintf(err, errlen, "config: bad ospf.router_id %s", out->ospf.router_id);
                goto derr;
            }
        } else {
            for (size_t i = 0; i < out->n_members; i++) {
                if (!strcmp(out->members[i].id, out->self) && out->members[i].sync_address.s_addr) {
                    inet_ntop(AF_INET, &out->members[i].sync_address, out->ospf.router_id,
                              sizeof(out->ospf.router_id));
                    break;
                }
            }
        }
    }

    /* Lease DB: relative names resolve against the shared config file's
     * directory; absolute names are used as given; none/off/no/~ opts out of the
     * file entirely (the daemon's own state file stays the persistence, and the
     * engine then starts with no stored lease); the key being absent keeps the
     * compiled-in default. An empty lease_file means opted out. */
    json_t *lv = json_object_get(root, "lease_file");
    const char *lf = NULL;
    int lf_mode; /* 1 = opted out, -1 = compiled-in default, 0 = path in lf */
    if (!lv)
        lf_mode = -1;
    else if (json_is_null(lv) || (json_is_boolean(lv) && !json_is_true(lv)))
        lf_mode = 1;
    else if (json_is_string(lv)) {
        lf = json_string_value(lv);
        if (!*lf || !strcmp(lf, "none") || !strcmp(lf, "off") || !strcmp(lf, "no"))
            lf_mode = 1;
        else
            lf_mode = 0;
    } else {
        snprintf(err, errlen, "config: lease_file must be a path or none");
        goto derr;
    }

    if (lf_mode == 1)
        out->lease_file[0] = '\0';
    else if (lf_mode == -1)
        snprintf(out->lease_file, HADC_PATH_MAX, "/var/lib/ha-dhcpc/dhclient.leases.%s",
                 out->interface);
    else if (lf[0] == '/')
        snprintf(out->lease_file, HADC_PATH_MAX, "%s", lf);
    else {
        char dir[HADC_PATH_MAX];
        char *slash = strrchr(out->base_path, '/');
        if (slash) {
            *slash = '\0';
            snprintf(dir, sizeof(dir), "%s", out->base_path);
            *slash = '/';
            snprintf(out->lease_file, HADC_PATH_MAX, "%s/%s", dir, lf);
        } else {
            snprintf(out->lease_file, HADC_PATH_MAX, "./%s", lf);
        }
    }

    json_decref(root);
    return 0;
derr:
    if (!err[0])
        snprintf(err, errlen, "%s", g_errbuf[0] ? g_errbuf : "config: schema error");
    json_decref(root);
    return -1;
}
