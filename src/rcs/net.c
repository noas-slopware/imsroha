// SPDX-License-Identifier: GPL-3.0-only
#include "net.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static int bind_device(GSocket *sock, const char *dev, GError **error)
{
	if (!dev || !dev[0])
		return 0;
	if (setsockopt(g_socket_get_fd(sock), SOL_SOCKET, SO_BINDTODEVICE, dev, (socklen_t)strlen(dev)) < 0) {
		int e = errno;
		g_set_error(error, G_IO_ERROR, g_io_error_from_errno(e),
			    "cannot bind to %s: %s", dev, g_strerror(e));
		return -1;
	}
	return 0;
}

/*
 * Idle TLS connections (the SIP registration, MSRP) stay open through
 * carrier NATs on the kernel's TCP keepalive: nothing in userspace wakes up.
 */
static void keepalive(GSocket *sock)
{
	int fd = g_socket_get_fd(sock), on = 1, idle = 120, intvl = 30, cnt = 4;
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
}

static GSocketConnection *connect_one(const struct rcs_config *cfg, GInetAddress *ia, uint16_t port,
				      unsigned timeout_s, GCancellable *cancel, GError **error)
{
	GSocketFamily fam = g_inet_address_get_family(ia);
	GSocket *sock = g_socket_new(fam, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, error);
	if (!sock)
		return NULL;
	const char *dev = cfg->interface;
	if (fam == G_SOCKET_FAMILY_IPV4 && cfg->interface4[0])
		dev = cfg->interface4;
	if (bind_device(sock, dev, error) < 0) {
		g_object_unref(sock);
		return NULL;
	}
	keepalive(sock);
	g_socket_set_timeout(sock, timeout_s);
	GSocketAddress *sa = g_inet_socket_address_new(ia, port);
	gboolean ok = g_socket_connect(sock, sa, cancel, error);
	g_object_unref(sa);
	if (!ok) {
		g_object_unref(sock);
		return NULL;
	}
	/* Reads block until data or close; timeouts are the callers'. */
	g_socket_set_timeout(sock, 0);
	GSocketConnection *c = g_socket_connection_factory_create_connection(sock);
	g_object_unref(sock);
	return c;
}

GIOStream *rcs_net_connect(const struct rcs_config *cfg, const char *host, uint16_t port,
			   int tls, unsigned timeout_s, GCancellable *cancel, GError **error)
{
	GResolver *res = g_resolver_get_default();
	GList *addrs = g_resolver_lookup_by_name(res, host, cancel, error);
	g_object_unref(res);
	if (!addrs)
		return NULL;

	GSocketConnection *conn = NULL;
	GError *last = NULL;
	for (GList *l = addrs; l && !conn; l = l->next) {
		g_clear_error(&last);
		conn = connect_one(cfg, l->data, port, timeout_s, cancel, &last);
	}
	g_resolver_free_addresses(addrs);
	if (!conn) {
		g_propagate_prefixed_error(error, last, "%s:%u: ", host, port);
		return NULL;
	}
	if (!tls)
		return G_IO_STREAM(conn);

	GSocketConnectable *ident = g_network_address_new(host, port);
	GIOStream *t = g_tls_client_connection_new(G_IO_STREAM(conn), ident, error);
	g_object_unref(ident);
	g_object_unref(conn);
	if (!t)
		return NULL;
	if (cfg->ca_file[0]) {
		GTlsDatabase *db = g_tls_file_database_new(cfg->ca_file, error);
		if (!db) {
			g_object_unref(t);
			return NULL;
		}
		g_tls_connection_set_database(G_TLS_CONNECTION(t), db);
		g_object_unref(db);
	}
	if (!g_tls_connection_handshake(G_TLS_CONNECTION(t), cancel, error)) {
		g_prefix_error(error, "TLS with %s: ", host);
		g_object_unref(t);
		return NULL;
	}
	return t;
}

struct connect_args {
	const struct rcs_config *cfg;
	char *host;
	uint16_t port;
	int tls;
	unsigned timeout_s;
};

static void connect_args_free(gpointer p)
{
	struct connect_args *a = p;
	g_free(a->host);
	g_free(a);
}

static void connect_thread(GTask *task, gpointer src, gpointer data, GCancellable *cancel)
{
	(void)src;
	struct connect_args *a = data;
	GError *e = NULL;
	GIOStream *s = rcs_net_connect(a->cfg, a->host, a->port, a->tls, a->timeout_s, cancel, &e);
	if (s)
		g_task_return_pointer(task, s, g_object_unref);
	else
		g_task_return_error(task, e);
}

void rcs_net_connect_async(const struct rcs_config *cfg, const char *host, uint16_t port,
			   int tls, unsigned timeout_s, GCancellable *cancel,
			   GAsyncReadyCallback cb, gpointer userdata)
{
	struct connect_args *a = g_new0(struct connect_args, 1);
	a->cfg = cfg;
	a->host = g_strdup(host);
	a->port = port;
	a->tls = tls;
	a->timeout_s = timeout_s;
	GTask *task = g_task_new(NULL, cancel, cb, userdata);
	g_task_set_task_data(task, a, connect_args_free);
	g_task_run_in_thread(task, connect_thread);
	g_object_unref(task);
}

GIOStream *rcs_net_connect_finish(GAsyncResult *res, GError **error)
{
	return g_task_propagate_pointer(G_TASK(res), error);
}

int rcs_net_local_address(GIOStream *s, char *addr, size_t size, uint16_t *port, int *v6)
{
	GIOStream *base = s;
	if (G_IS_TLS_CONNECTION(s))
		g_object_get(s, "base-io-stream", &base, NULL);
	else
		g_object_ref(base);
	int r = -ENOTCONN;
	if (G_IS_SOCKET_CONNECTION(base)) {
		GSocketAddress *sa = g_socket_connection_get_local_address(G_SOCKET_CONNECTION(base), NULL);
		if (sa && G_IS_INET_SOCKET_ADDRESS(sa)) {
			GInetAddress *ia = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(sa));
			char *t = g_inet_address_to_string(ia);
			snprintf(addr, size, "%s", t);
			g_free(t);
			if (port)
				*port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(sa));
			if (v6)
				*v6 = g_inet_address_get_family(ia) == G_SOCKET_FAMILY_IPV6;
			r = 0;
		}
		if (sa)
			g_object_unref(sa);
	}
	g_object_unref(base);
	return r;
}

void rcs_net_set_timeout(GIOStream *s, unsigned timeout_s)
{
	GIOStream *base = s;
	if (G_IS_TLS_CONNECTION(s))
		g_object_get(s, "base-io-stream", &base, NULL);
	else
		g_object_ref(base);
	if (G_IS_SOCKET_CONNECTION(base))
		g_socket_set_timeout(g_socket_connection_get_socket(G_SOCKET_CONNECTION(base)), timeout_s);
	g_object_unref(base);
}
