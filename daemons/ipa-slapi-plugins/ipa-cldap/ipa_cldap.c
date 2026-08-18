/** BEGIN COPYRIGHT BLOCK
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GPLv3 section 7:
 *
 * In the following paragraph, "GPL" means the GNU General Public
 * License, version 3 or any later version, and "Non-GPL Code" means
 * code that is governed neither by the GPL nor a license
 * compatible with the GPL.
 *
 * You may link the code of this Program with Non-GPL Code and convey
 * linked combinations including the two, provided that such Non-GPL
 * Code only links to the code of this Program through those well
 * defined interfaces identified in the file named EXCEPTION found in
 * the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline
 * functions from the Approved Interfaces without causing the resulting
 * work to be covered by the GPL. Only the copyright holders of this
 * Program may make changes or additions to the list of Approved
 * Interfaces.
 *
 * Authors:
 * Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include <netdb.h>

#include "ipa_cldap.h"
#include "util.h"

Slapi_PluginDesc ipa_cldap_desc = {
    IPA_CLDAP_PLUGIN_NAME,
    "FreeIPA project",
    "FreeIPA/3.0",
    IPA_CLDAP_PLUGIN_DESC
};

static int ipa_cldap_start(Slapi_PBlock *pb)
{
    struct ipa_cldap_ctx *ctx;
    int ret;

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &ctx);
    if (ret) {
        LOG_FATAL("No plugin context ?!\n");
        return -1;
    }

    ret = pthread_create(&ctx->tid, NULL, ipa_cldap_worker, ctx);
    if (ret) {
        LOG_FATAL("Failed to create worker thread\n");
        return -1;
    }

    LOG("Plugin statrup completed.\n");

    return 0;
}

static int ipa_cldap_stop(Slapi_PBlock *pb)
{
    struct ipa_cldap_ctx *ctx;
    void *retval;
    size_t i;
    int ret;

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &ctx);
    if (ret) {
        LOG_FATAL("No plugin context ?!\n");
        return -1;
    }

    /* send stop signal to terminate worker thread */
    do {
        ret = write(ctx->stopfd[1], "", 1);
    } while (ret == -1 && errno == EINTR);
    close(ctx->stopfd[1]);

    ret = pthread_join(ctx->tid, &retval);
    if (ret) {
        LOG_FATAL("Failed to stop worker thread\n");
        return -1;
    }

    for (i = 0; i < ctx->num_sds; i++) {
        close(ctx->sds[i]);
    }
    free(ctx->sds);
    ctx->sds = NULL;
    ctx->num_sds = 0;
    slapi_ch_free_string(&ctx->server_name);

    LOG("Plugin shutdown completed.\n");

    return 0;
}

static int ipa_cldap_bind_address(int family,
                                  const struct sockaddr *addr,
                                  socklen_t addrlen,
                                  bool v6only,
                                  int *sd_out)
{
    int sd;
    int flags;
    int val;
    int ret;

    sd = socket(family, SOCK_DGRAM, 0);
    if (sd == -1) {
        ret = errno;
        LOG_FATAL("Failed to create CLDAP socket (%d, %s)\n",
                  ret, strerror(ret));
        return ret;
    }

    val = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) == -1) {
        ret = errno;
        LOG("Failed to make socket immediately reusable (%d, %s)\n",
            ret, strerror(ret));
    }

    if (family == AF_INET6 && v6only) {
        val = 1;
        if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY,
                       &val, sizeof(val)) == -1) {
            ret = errno;
            LOG_FATAL("Failed to restrict IPv6 CLDAP socket (%d, %s)\n",
                      ret, strerror(ret));
            close(sd);
            return ret;
        }
    }

    if (bind(sd, addr, addrlen) == -1) {
        ret = errno;
        LOG_FATAL("Failed to bind CLDAP socket (%d, %s)\n",
                  ret, strerror(ret));
        close(sd);
        return ret;
    }

    flags = fcntl(sd, F_GETFL);
    if (flags == -1 || fcntl(sd, F_SETFL, flags | O_NONBLOCK) == -1) {
        ret = errno;
        LOG_FATAL("Failed to set CLDAP socket to non-blocking (%d, %s)\n",
                  ret, strerror(ret));
        close(sd);
        return ret;
    }

    *sd_out = sd;
    return 0;
}

static int ipa_cldap_init_service(Slapi_PBlock *pb,
                                  struct ipa_cldap_ctx **cldap_ctx)
{
    struct ipa_cldap_ctx *ctx;
    struct sockaddr_in6 wildcard_addr;
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    Slapi_Entry *e;
    char *listen_host = NULL;
    size_t address_count = 0;
    size_t i;
    int ret;

    ctx = calloc(1, sizeof(struct ipa_cldap_ctx));
    if (!ctx) {
        return ENOMEM;
    }

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &ctx->plugin_id);
    if ((ret != 0) || (NULL == ctx->plugin_id)) {
        LOG_FATAL("Could not get identity or identity was NULL\n");
        if (ret == 0) {
            ret = -1;
        }
        goto done;
    }

    slapi_pblock_get(pb, SLAPI_PLUGIN_CONFIG_ENTRY, &e);
    if (!e) {
        LOG_FATAL("Plugin configuration not found!\n");
        ret = -1;
        goto done;
    }

    ctx->base_dn = slapi_entry_attr_get_charptr(e, "nsslapd-basedn");
    if (!ctx->base_dn) {
        LOG_FATAL("Plugin configuration not found!\n");
        ret = -1;
        goto done;
    }

    ret = pipe(ctx->stopfd);
    if (ret != 0) {
        LOG_FATAL("Failed to stop pipe\n");
        ret = EIO;
        goto done;
    }

    listen_host = slapi_entry_attr_get_charptr(e, "nsslapd-listenhost");
    if (!listen_host) {
        ctx->sds = calloc(1, sizeof(int));
        if (!ctx->sds) {
            ret = ENOMEM;
            goto done;
        }

        memset(&wildcard_addr, 0, sizeof(wildcard_addr));
        wildcard_addr.sin6_family = AF_INET6;
        wildcard_addr.sin6_port = htons(CLDAP_PORT);
        wildcard_addr.sin6_addr = in6addr_any;

        ret = ipa_cldap_bind_address(
            AF_INET6,
            (struct sockaddr *)&wildcard_addr,
            sizeof(wildcard_addr),
            false,
            &ctx->sds[0]);
        if (ret != 0) {
            goto done;
        }
        ctx->num_sds = 1;
    } else {
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_NUMERICSERV;

        ret = getaddrinfo(listen_host, "389", &hints, &result);
        if (ret != 0) {
            LOG_FATAL("Failed to resolve CLDAP listen host %s: %s\n",
                      listen_host, gai_strerror(ret));
            ret = EINVAL;
            goto done;
        }

        for (rp = result; rp != NULL; rp = rp->ai_next) {
            if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6) {
                address_count++;
            }
        }
        if (address_count == 0) {
            LOG_FATAL("CLDAP listen host %s has no IPv4 or IPv6 addresses\n",
                      listen_host);
            ret = EADDRNOTAVAIL;
            goto done;
        }

        ctx->sds = calloc(address_count, sizeof(int));
        if (!ctx->sds) {
            ret = ENOMEM;
            goto done;
        }

        for (rp = result; rp != NULL; rp = rp->ai_next) {
            if (rp->ai_family != AF_INET && rp->ai_family != AF_INET6) {
                continue;
            }
            ret = ipa_cldap_bind_address(
                rp->ai_family,
                rp->ai_addr,
                rp->ai_addrlen,
                true,
                &ctx->sds[ctx->num_sds]);
            if (ret != 0) {
                goto done;
            }
            ctx->num_sds++;
        }
        ctx->server_name = listen_host;
        listen_host = NULL;
    }

    ret = 0;

done:
    if (result) {
        freeaddrinfo(result);
    }
    if (listen_host) {
        slapi_ch_free_string(&listen_host);
    }
    if (ret) {
        if (ctx->sds) {
            for (i = 0; i < ctx->num_sds; i++) {
                close(ctx->sds[i]);
            }
            free(ctx->sds);
        }
        slapi_ch_free_string(&ctx->server_name);
        if (ctx->stopfd[0] > 0) {
            close(ctx->stopfd[0]);
        }
        if (ctx->stopfd[1] > 0) {
            close(ctx->stopfd[1]);
        }
        free(ctx);
    } else {
        *cldap_ctx = ctx;
    }
    return ret;
}

static int ipa_cldap_post_init(Slapi_PBlock *pb)
{
    return 0;
}

/* Initialization function */
int ipa_cldap_init(Slapi_PBlock *pb)
{
    struct ipa_cldap_ctx *cldap_ctx = NULL;
    int ret;

    ret = ipa_cldap_init_service(pb, &cldap_ctx);
    if (ret) {
        LOG_FATAL("Failed to initialize CLDAP Plugin\n");
        /* do not cause DS to stop, simply do nothing */
        return 0;
    }

    /* Register the plug-in */
    ret = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_03);
    if (!ret) {
        ret = slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, &ipa_cldap_desc);
    }
    if (!ret) {
        ret = slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN, &ipa_cldap_start);
    }
    if (!ret) {
        ret = slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN, &ipa_cldap_stop);
    }
    if (!ret) {
        ret = slapi_pblock_set(pb, SLAPI_PLUGIN_PRIVATE, cldap_ctx);
    }
    if (ret) {
        LOG_FATAL("Failed to initialize plug-in\n" );
        return -1;
    }

    slapi_register_plugin("postoperation", 1,
                          "ipa_cldap_post_init",
                          ipa_cldap_post_init,
                          "CLDAP post ops", NULL,
                          cldap_ctx->plugin_id);

    return 0;
}
