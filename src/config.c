/* Config loaders: YAML (libyaml) -> jansson -> typed structs (plan §6). */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <jansson.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

#include "ha-dhcpc/config.h"
#include "ha-dhcpc/log.h"

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
            json_array_append(arr, parse_node(doc, child));
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
            json_object_set(obj, (const char *)k->data.scalar.value, parse_node(doc, v));
        }
        return obj;
    }
    default:
        return json_null();
    }
}

static json_t *yaml_file_to_json(const char *path, char *err, size_t errlen)
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
    if (!root || root->type != YAML_MAPPING_NODE) {
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

/* ---- schema extraction helpers ---- */

static char g_errbuf[512];

static int get_str(json_t *o, const char *key, char *dst, size_t dstsz, bool required,
                   const char *what)
{
    json_t *v = json_object_get(o, key);
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
    json_t *v = json_object_get(o, key);
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
    json_t *v = json_object_get(o, key);
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

static int parse_mac(const char *s, uint8_t out[HADC_MAC_LEN])
{
    unsigned b[6];
    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        out[i] = (uint8_t)b[i];
    return 0;
}

/* ---- loaders ---- */

int hadc_config_load_master(const char *path, hadc_master_conf_t *out, char *err, size_t errlen)
{
    json_t *root = yaml_file_to_json(path, err, errlen);
    if (!root)
        return -1;
    memset(out, 0, sizeof(*out));

    char mac[64];
    if (get_str(root, "designated_master", out->designated_master,
                HADC_NODE_ID_MAX, true, "master.conf") ||
        get_str(root, "master_mac", mac, sizeof(mac), true, "master.conf")) {
        snprintf(err, errlen, "%s", g_errbuf);
        json_decref(root);
        return -1;
    }
    if (parse_mac(mac, out->master_mac) != 0) {
        snprintf(err, errlen, "master.conf: bad master_mac %s", mac);
        json_decref(root);
        return -1;
    }
    json_t *members = json_object_get(root, "members");
    if (members && json_is_array(members)) {
        json_t *m;
        size_t idx;
        json_array_foreach(members, idx, m) {
            if (out->n_members >= HADC_MEMBERS_MAX) {
                snprintf(err, errlen, "master.conf: too many members");
                json_decref(root);
                return -1;
            }
            hadc_member_t *mm = &out->members[out->n_members++];
            if (get_str(m, "id", mm->id, HADC_NODE_ID_MAX, true, "master.conf member")) {
                snprintf(err, errlen, "%s", g_errbuf);
                json_decref(root);
                return -1;
            }
            char addr[64];
            if (get_str(m, "sync_address", addr, sizeof(addr), true, "master.conf member") ||
                inet_pton(AF_INET, addr, &mm->sync_address) != 1) {
                snprintf(err, errlen, "master.conf member %s: bad sync_address", mm->id);
                json_decref(root);
                return -1;
            }
        }
    }
    json_decref(root);
    return 0;
}

int hadc_config_load_slave(const char *path, hadc_slave_conf_t *out, char *err, size_t errlen)
{
    json_t *root = yaml_file_to_json(path, err, errlen);
    if (!root)
        return -1;
    memset(out, 0, sizeof(*out));
    long long prio;
    if (get_str(root, "self", out->self, HADC_NODE_ID_MAX, true, "slave.conf") ||
        get_int(root, "priority", &prio, 100, false, "slave.conf")) {
        snprintf(err, errlen, "%s", g_errbuf);
        json_decref(root);
        return -1;
    }
    out->priority = (int)prio;
    json_decref(root);
    return 0;
}

int hadc_config_load_daemon(const char *path, hadc_daemon_conf_t *out, char *err, size_t errlen)
{
    json_t *root = yaml_file_to_json(path, err, errlen);
    if (!root)
        return -1;
    memset(out, 0, sizeof(*out));
    long long v;

    if (get_str(root, "interface", out->interface, HADC_IFNAME_MAX, true, "ha-dhcpc.yaml")) {
        snprintf(err, errlen, "%s", g_errbuf);
        json_decref(root);
        return -1;
    }

    json_t *c = json_object_get(root, "cluster");
    if (get_int(c ? c : root, "port", &v, 4227, false, "cluster")) goto derr;
    out->cluster.port = (uint16_t)v;
    if (get_int(c ? c : root, "heartbeat_ms", &v, 2000, false, "cluster")) goto derr;
    out->cluster.heartbeat_ms = (uint32_t)v;
    if (get_int(c ? c : root, "election_deadline_ms", &v, 6000, false, "cluster")) goto derr;
    out->cluster.election_deadline_ms = (uint32_t)v;
    out->cluster.quorum = HADC_QUORUM_MAJORITY;

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
        snprintf(err, errlen, "ha-dhcpc.yaml: unknown retention %s", ret);
        goto derr;
    }
    if (get_int(d ? d : root, "retention_max_duration_s", &v, 0, false, "dhcp")) goto derr;
    out->dhcp.retention_max_duration_s = (uint64_t)v;
    json_t *rr = d ? json_object_get(d, "rediscover_in_retention") : NULL;
    out->dhcp.rediscover_in_retention = rr && json_is_boolean(rr) ? json_is_true(rr) : true;
    if (get_int(d ? d : root, "rate_limit_ms", &v, 0, false, "dhcp")) goto derr;
    if (v < 0 || v > 3600000) {
        snprintf(err, errlen, "ha-dhcpc.yaml: rate_limit_ms out of range 0..3600000");
        goto derr;
    }
    out->dhcp.rate_limit_ms = (uint32_t)v;
    json_t *ro = d ? json_object_get(d, "request_options") : NULL;
    if (ro && json_is_array(ro)) {
        json_t *e;
        size_t idx;
        json_array_foreach(ro, idx, e) {
            if (!json_is_integer(e) || json_integer_value(e) < 0 || json_integer_value(e) > 255 ||
                out->dhcp.n_request_options >= HADC_OPTS_MAX) {
                snprintf(err, errlen, "ha-dhcpc.yaml: bad request_options entry");
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
    snprintf(out->apply.dns_hook, HADC_PATH_MAX, "%s",
             (a && json_object_get(a, "dns_hook") && json_is_string(json_object_get(a, "dns_hook")))
                 ? json_string_value(json_object_get(a, "dns_hook"))
                 : "");
    out->apply.suppress_member_dad = true;
    out->apply.arp_responder = true;
    out->apply.announce_gratuitous = true;
    if (a) {
        if (get_bool(a, "suppress_member_dad", &out->apply.suppress_member_dad, true)) goto derr;
        if (get_bool(a, "arp_responder", &out->apply.arp_responder, true)) goto derr;
        if (get_bool(a, "announce_gratuitous", &out->apply.announce_gratuitous, true)) goto derr;
    }

    if (get_str(root, "ctl_socket", out->ctl_socket, HADC_PATH_MAX, false, "ha-dhcpc.yaml"))
        goto derr;
    if (!out->ctl_socket[0])
        snprintf(out->ctl_socket, HADC_PATH_MAX, "/run/ha-dhcpc.ctl");

    json_decref(root);
    return 0;
derr:
    snprintf(err, errlen, "%s", g_errbuf[0] ? g_errbuf : "ha-dhcpc.yaml: schema error");
    json_decref(root);
    return -1;
}
