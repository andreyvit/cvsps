/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <stdarg.h>
#include <zlib.h>
#include <sys/socket.h>
#include <cbtcommon/debug.h>
#include <cbtcommon/text_util.h>
#include <cbtcommon/tcpsocket.h>
#include <cbtcommon/sio.h>

#include "cvs_direct.h"
#include "util.h"

#define RD_BUFF_SIZE 4096

struct _CvsServerCtx 
{
    int read_fd;
    int write_fd;
    char root[PATH_MAX];

    int is_pserver;

    /* buffered reads from descriptor */
    char read_buff[RD_BUFF_SIZE];
    char * head;
    char * tail;

    int compressed;
    z_stream zout;
    z_stream zin;

    /* when reading compressed data, the compressed data buffer */
    char zread_buff[RD_BUFF_SIZE];
};

static void get_cvspass(char *, const char *);
static void send_string(CvsServerCtx *, const char *, ...);
static int read_response(CvsServerCtx *, const char *);
static void ctx_to_fp(CvsServerCtx * ctx, FILE * fp);
static int read_line(CvsServerCtx * ctx, char * p);

static CvsServerCtx * open_ctx_pserver(CvsServerCtx *, const char *);
static CvsServerCtx * open_ctx_forked(CvsServerCtx *, const char *);

CvsServerCtx * open_cvs_server(char * p_root, int compress)
{
    CvsServerCtx * ctx = (CvsServerCtx*)malloc(sizeof(*ctx));
    char root[PATH_MAX];
    char * p = root, *tok;

    if (!ctx)
	return NULL;

    ctx->head = ctx->tail = ctx->read_buff;
    ctx->read_fd = ctx->write_fd = -1;
    ctx->compressed = 0;
    ctx->is_pserver = 0;

    if (compress)
    {
	memset(&ctx->zout, 0, sizeof(z_stream));
	memset(&ctx->zin, 0, sizeof(z_stream));
	
	/* 
	 * to 'prime' the reads, make it look like there was output
	 * room available (i.e. we have processed all pending compressed 
	 * data
	 */
	ctx->zin.avail_out = 1;
	
	if (deflateInit(&ctx->zout, compress) != Z_OK)
	{
	    free(ctx);
	    return NULL;
	}
	
	if (inflateInit(&ctx->zin) != Z_OK)
	{
	    deflateEnd(&ctx->zout);
	    free(ctx);
	    return NULL;
	}
    }

    strcpy(root, p_root);

    tok = strsep(&p, ":");

    /* if root string looks like :pserver:... then the first token will be empty */
    if (strlen(tok) == 0)
    {
	char * method = strsep(&p, ":");
	if (strcmp(method, "pserver") == 0)
	{
	    ctx = open_ctx_pserver(ctx, p);
	}
	else if (strstr("local:ext:fork:server", method))
	{
	    /* handle all of these via fork, even local */
	    ctx = open_ctx_forked(ctx, p);
	}
	else
	{
	    debug(DEBUG_APPERROR, "cvs_direct: unsupported cvs access method: %s", method);
	    free(ctx);
	    ctx = NULL;
	}
    }
    else
    {
	ctx = open_ctx_forked(ctx, p_root);
    }

    if (ctx)
    {
	char buff[BUFSIZ];

	send_string(ctx, "Root %s\n", ctx->root);

	/* this is taken from 1.11.1p1 trace - but with Mbinary removed. we can't handle it (yet!) */
	send_string(ctx, "Valid-responses ok error Valid-requests Checked-in New-entry Checksum Copy-file Updated Created Update-existing Merged Patched Rcs-diff Mode Mod-time Removed Remove-entry Set-static-directory Clear-static-directory Set-sticky Clear-sticky Template Set-checkin-prog Set-update-prog Notified Module-expansion Wrapper-rcsOption M E F LOGM\n", ctx->root);

	send_string(ctx, "valid-requests\n");

	/* check for the commands we will issue */
	read_line(ctx, buff);
	if (strncmp(buff, "Valid-requests", 14) != 0)
	{
	    debug(DEBUG_APPERROR, "cvs_direct: bad response to valid-requests command");
	    close_cvs_server(ctx);
	    return NULL;
	}

	if (!strstr(buff, " version") ||
	    !strstr(buff, " rlog") ||
	    !strstr(buff, " rdiff") || 
	    !strstr(buff, " diff") ||
	    !strstr(buff, " co"))
	{
	    debug(DEBUG_APPERROR, "cvs_direct: cvs server too old for cvs_direct");
	    close_cvs_server(ctx);
	    return NULL;
	}
	
	read_line(ctx, buff);
	if (strcmp(buff, "ok") != 0)
	{
	    debug(DEBUG_APPERROR, "cvs_direct: bad ok trailer to valid-requests command");
	    close_cvs_server(ctx);
	    return NULL;
	}

	/* this is myterious but 'mandatory' */
	send_string(ctx, "UseUnchanged\n");

	if (compress)
	{
	    send_string(ctx, "Gzip-stream %d\n", compress);
	    ctx->compressed = 1;
	}

	debug(DEBUG_APPMSG1, "cvs_direct initialized to CVSROOT %s", ctx->root);
    }

    return ctx;
}

static CvsServerCtx * open_ctx_pserver(CvsServerCtx * ctx, const char * p_root)
{
    char root[PATH_MAX];
    char full_root[PATH_MAX];
    char * p = root, *tok, *tok2;
    char user[BUFSIZ];
    char server[BUFSIZ];
    char pass[BUFSIZ];
    char port[8];

    strcpy(root, p_root);

    tok = strsep(&p, ":");
    if (strlen(tok) == 0 || !p)
    {
	debug(DEBUG_APPERROR, "parse error on third token");
	goto out_free_err;
    }

    tok2 = strsep(&tok, "@");
    if (!strlen(tok2) || (!tok || !strlen(tok)))
    {
	debug(DEBUG_APPERROR, "parse error on user@server in pserver");
	goto out_free_err;
    }

    strcpy(user, tok2);
    strcpy(server, tok);
    
    if (*p != '/')
    {
	tok = strchr(p, '/');
	if (!tok)
	{
	    debug(DEBUG_APPERROR, "parse error: expecting / in root");
	    goto out_free_err;
	}
	
	memset(port, 0, sizeof(port));
	memcpy(port, p, tok - p);

	p = tok;
    }
    else
    {
	strcpy(port, "2401");
    }

    /* the line from .cvspass is fully qualified, so rebuild */
    snprintf(full_root, PATH_MAX, ":pserver:%s@%s:%s%s", user, server, port, p);
    get_cvspass(pass, full_root);

    debug(DEBUG_TCP, "user:%s server:%s port:%s pass:%s full_root:%s", user, server, port, pass, full_root);

    if ((ctx->read_fd = tcp_create_socket(REUSE_ADDR)) < 0)
	goto out_free_err;

    ctx->write_fd = dup(ctx->read_fd);

    if (tcp_connect(ctx->read_fd, server, atoi(port)) < 0)
	goto out_close_err;
    
    send_string(ctx, "BEGIN AUTH REQUEST\n");
    send_string(ctx, "%s\n", p);
    send_string(ctx, "%s\n", user);
    send_string(ctx, "%s\n", pass);
    send_string(ctx, "END AUTH REQUEST\n");

    if (!read_response(ctx, "I LOVE YOU"))
	goto out_close_err;

    strcpy(ctx->root, p);
    ctx->is_pserver = 1;

    return ctx;

 out_close_err:
    close(ctx->read_fd);
 out_free_err:
    free(ctx);
    return NULL;
}

static CvsServerCtx * open_ctx_forked(CvsServerCtx * ctx, const char * p_root)
{
    char root[PATH_MAX];
    char * p = root, *tok, *tok2, *rep;
    char execcmd[PATH_MAX];
    int to_cvs[2];
    int from_cvs[2];
    pid_t pid;
    const char * cvs_server = getenv("CVS_SERVER");

    if (!cvs_server)
	cvs_server = "cvs";

    strcpy(root, p_root);

    /* if there's a ':', it's remote */
    tok = strsep(&p, ":");

    if (p)
    {
	const char * cvs_rsh = getenv("CVS_RSH");

	if (!cvs_rsh)
	    cvs_rsh = "rsh";

	tok2 = strsep(&tok, "@");

	if (tok)
	    snprintf(execcmd, PATH_MAX, "%s -l %s %s %s server", cvs_rsh, tok2, tok, cvs_server);
	else
	    snprintf(execcmd, PATH_MAX, "%s %s %s server", cvs_rsh, tok2, cvs_server);

	rep = p;
    }
    else
    {
	snprintf(execcmd, PATH_MAX, "%s server", cvs_server);
	rep = tok;
    }

    if (pipe(to_cvs) < 0)
    {
	debug(DEBUG_SYSERROR, "cvs_direct: failed to create pipe to_cvs");
	goto out_free_err;
    }

    if (pipe(from_cvs) < 0)
    {
	debug(DEBUG_SYSERROR, "cvs_direct: failed to create pipe from_cvs");
	goto out_close_err;
    }

    debug(DEBUG_TCP, "forked cmdline: %s", execcmd);

    if ((pid = fork()) < 0)
    {
	debug(DEBUG_SYSERROR, "cvs_direct: can't fork");
	goto out_close2_err;
    }
    else if (pid == 0) /* child */
    {
	char * argp[4];
	argp[0] = "sh";
	argp[1] = "-c";
	argp[2] = execcmd;
	argp[3] = NULL;

	close(to_cvs[1]);
	close(from_cvs[0]);
	
	close(0);
	dup(to_cvs[0]);
	close(1);
	dup(from_cvs[1]);

	execv("/bin/sh",argp);

	debug(DEBUG_APPERROR, "cvs_direct: fatal: shouldn't be reached");
	exit(1);
    }

    close(to_cvs[0]);
    close(from_cvs[1]);
    ctx->read_fd = from_cvs[0];
    ctx->write_fd = to_cvs[1];

    strcpy(ctx->root, rep);

    return ctx;

 out_close2_err:
    close(from_cvs[0]);
    close(from_cvs[1]);
 out_close_err:
    close(to_cvs[0]);
    close(to_cvs[1]);
 out_free_err:
    free(ctx);
    return NULL;
}

void close_cvs_server(CvsServerCtx * ctx)
{
    /* FIXME: some sort of flushing should be done for non-compressed case */

    if (ctx->compressed)
    {
	int ret, len;
	char buff[BUFSIZ];

	/* 
	 * there shouldn't be anything left, but we do want
	 * to send an 'end of stream' marker, (if such a thing
	 * actually exists..)
	 */
	do
	{
	    ctx->zout.next_out = buff;
	    ctx->zout.avail_out = BUFSIZ;
	    ret = deflate(&ctx->zout, Z_FINISH);

	    if ((ret == Z_OK || ret == Z_STREAM_END) && ctx->zout.avail_out != BUFSIZ)
	    {
		len = BUFSIZ - ctx->zout.avail_out;
		if (writen(ctx->write_fd, buff, len) != len)
		    debug(DEBUG_APPERROR, "cvs_direct: zout: error writing final state");
		    
		//hexdump(buff, len, "cvs_direct: zout: sending unsent data");
	    }
	} while (ret == Z_OK);

	if ((ret = deflateEnd(&ctx->zout)) != Z_OK)
	    debug(DEBUG_APPERROR, "cvs_direct: zout: deflateEnd error: %s: %s", 
		  (ret == Z_STREAM_ERROR) ? "Z_STREAM_ERROR":"Z_DATA_ERROR", ctx->zout.msg);
    }
    
    /* we're done writing now */
    debug(DEBUG_TCP, "cvs_direct: closing cvs server write connection %d", ctx->write_fd);
    close(ctx->write_fd);

    /* 
     * if this is pserver, then read_fd is a bi-directional socket.
     * we want to shutdown the write side, just to make sure the 
     * server get's eof
     */
    if (ctx->is_pserver)
    {
	debug(DEBUG_TCP, "cvs_direct: shutdown on read socket");
	if (shutdown(ctx->read_fd, SHUT_WR) < 0)
	    debug(DEBUG_SYSERROR, "cvs_direct: error with shutdown on pserver socket");
    }

    if (ctx->compressed)
    {
	int ret = Z_OK, len, eof = 0;
	char buff[BUFSIZ];

	/* read to the 'eof'/'eos' marker.  there are two states we 
	 * track, looking for Z_STREAM_END (application level EOS)
	 * and EOF on socket.  Both should happen at the same time,
	 * but we need to do the read first, the first time through
	 * the loop, but we want to do one read after getting Z_STREAM_END
	 * too.  so this loop has really ugly exit conditions.
	 */
	for(;;)
	{
	    /*
	     * if there's nothing in the avail_in, and we
	     * inflated everything last pass (avail_out != 0)
	     * then slurp some more from the descriptor, 
	     * if we get EOF, exit the loop
	     */
	    if (ctx->zin.avail_in == 0 && ctx->zin.avail_out != 0)
	    {
		debug(DEBUG_TCP, "cvs_direct: doing final slurp");
		len = read(ctx->read_fd, ctx->zread_buff, RD_BUFF_SIZE);
		debug(DEBUG_TCP, "cvs_direct: did final slurp: %d", len);

		if (len <= 0)
		{
		    eof = 1;
		    break;
		}

		/* put the data into the inflate input stream */
		ctx->zin.next_in = ctx->zread_buff;
		ctx->zin.avail_in = len;
	    }

	    /* 
	     * if the last time through we got Z_STREAM_END, and we 
	     * get back here, it means we should've gotten EOF but
	     * didn't
	     */
	    if (ret == Z_STREAM_END)
		break;

	    ctx->zin.next_out = buff;
	    ctx->zin.avail_out = BUFSIZ;

	    ret = inflate(&ctx->zin, Z_SYNC_FLUSH);
	    len = BUFSIZ - ctx->zin.avail_out;
	    
	    if (ret == Z_BUF_ERROR)
		debug(DEBUG_APPERROR, "Z_BUF_ERROR");

	    if (ret == Z_OK && len == 0)
		debug(DEBUG_TCP, "cvs_direct: no data out of inflate");

	    if (ret == Z_STREAM_END)
		debug(DEBUG_TCP, "cvs_direct: got Z_STREAM_END");

	    if ((ret == Z_OK || ret == Z_STREAM_END) && len > 0)
		hexdump(buff, BUFSIZ - ctx->zin.avail_out, "cvs_direct: zin: unread data at close");
	}

	if (ret != Z_STREAM_END)
	    debug(DEBUG_APPERROR, "cvs_direct: zin: Z_STREAM_END not encountered (premature EOF?)");

	if (eof == 0)
	    debug(DEBUG_APPERROR, "cvs_direct: zin: EOF not encountered (premature Z_STREAM_END?)");

	if ((ret = inflateEnd(&ctx->zin)) != Z_OK)
	    debug(DEBUG_APPERROR, "cvs_direct: zin: inflateEnd error: %s: %s", 
		  (ret == Z_STREAM_ERROR) ? "Z_STREAM_ERROR":"Z_DATA_ERROR", ctx->zin.msg ? ctx->zin.msg : "");
    }

    debug(DEBUG_TCP, "cvs_direct: closing cvs server read connection %d", ctx->read_fd);
    close(ctx->read_fd);

    free(ctx);
}

static void get_cvspass(char * pass, const char * root)
{
    char cvspass[PATH_MAX];
    const char * home;
    FILE * fp;

    pass[0] = 0;

    if (!(home = getenv("HOME")))
    {
	debug(DEBUG_APPERROR, "HOME environment variable not set");
	exit(1);
    }

    if (snprintf(cvspass, PATH_MAX, "%s/.cvspass", home) >= PATH_MAX)
    {
	debug(DEBUG_APPERROR, "prefix buffer overflow");
	exit(1);
    }
    
    if ((fp = fopen(cvspass, "r")))
    {
	char buff[BUFSIZ];
	int len = strlen(root);

	while (fgets(buff, BUFSIZ, fp))
	{
	    /* FIXME: what does /1 mean? */
	    if (strncmp(buff, "/1 ", 3) != 0)
		continue;

	    if (strncmp(buff + 3, root, len) == 0)
	    {
		strcpy(pass, buff + 3 + len + 1);
		chop(pass);
		break;
	    }
		
	}
	fclose(fp);
    }

    if (!pass[0])
	pass[0] = 'A';
}

static void send_string(CvsServerCtx * ctx, const char * str, ...)
{
    int len;
    char buff[BUFSIZ];
    va_list ap;

    va_start(ap, str);

    len = vsnprintf(buff, BUFSIZ, str, ap);
    if (len >= BUFSIZ)
    {
	debug(DEBUG_APPERROR, "cvs_direct: command send string overflow");
	exit(1);
    }

    if (ctx->compressed)
    {
	char zbuff[BUFSIZ];

	if  (ctx->zout.avail_in != 0)
	{
	    debug(DEBUG_APPERROR, "cvs_direct: zout: last output command not flushed");
	    exit(1);
	}

	ctx->zout.next_in = buff;
	ctx->zout.avail_in = len;
	ctx->zout.avail_out = 0;

	while (ctx->zout.avail_in > 0 || ctx->zout.avail_out == 0)
	{
	    int ret;

	    ctx->zout.next_out = zbuff;
	    ctx->zout.avail_out = BUFSIZ;
	    
	    /* FIXME: for the arguments before a command, flushing is counterproductive */
	    ret = deflate(&ctx->zout, Z_SYNC_FLUSH);
	    
	    if (ret == Z_OK)
	    {
		len = BUFSIZ - ctx->zout.avail_out;
		
		if (writen(ctx->write_fd, zbuff, len) != len)
		{
		    debug(DEBUG_SYSERROR, "cvs_direct: zout: can't write");
		    exit(1);
		}
	    }
	    else
	    {
		debug(DEBUG_APPERROR, "cvs_direct: zout: error %d %s", ret, ctx->zout.msg);
	    }
	}
    }
    else
    {
	if (writen(ctx->write_fd, buff, len)  != len)
	{
	    debug(DEBUG_SYSERROR, "cvs_direct: can't send command");
	    exit(1);
	}
    }

    debug(DEBUG_TCP, "string: '%s' sent", buff);
}

static int refill_buffer(CvsServerCtx * ctx)
{
    int len;

    if (ctx->head != ctx->tail)
    {
	debug(DEBUG_APPERROR, "cvs_direct: refill_buffer called on non-empty buffer");
	exit(1);
    }

    ctx->head = ctx->read_buff;
    len = RD_BUFF_SIZE;
	
    if (ctx->compressed)
    {
	int zlen, ret;

	/* if there was leftover buffer room, it's time to slurp more data */
	do 
	{
	    if (ctx->zin.avail_out > 0)
	    {
		if (ctx->zin.avail_in != 0)
		{
		    debug(DEBUG_APPERROR, "cvs_direct: zin: expect 0 avail_in");
		    exit(1);
		}
		zlen = read(ctx->read_fd, ctx->zread_buff, RD_BUFF_SIZE);
		ctx->zin.next_in = ctx->zread_buff;
		ctx->zin.avail_in = zlen;
	    }
	    
	    ctx->zin.next_out = ctx->head;
	    ctx->zin.avail_out = len;
	    
	    /* FIXME: we don't always need Z_SYNC_FLUSH, do we? */
	    ret = inflate(&ctx->zin, Z_SYNC_FLUSH);
	}
	while (ctx->zin.avail_out == len);

	if (ret == Z_OK)
	{
	    ctx->tail = ctx->head + (len - ctx->zin.avail_out);
	}
	else
	{
	    debug(DEBUG_APPERROR, "cvs_direct: zin: error %d %s", ret, ctx->zin.msg);
	    exit(1);
	}
    }
    else
    {
	len = read(ctx->read_fd, ctx->head, len);
	ctx->tail = (len <= 0) ? ctx->head : ctx->head + len;
    }

    return len;
}

static int read_line(CvsServerCtx * ctx, char * p)
{
    int len = 0;
    while (1)
    {
	if (ctx->head == ctx->tail)
	    if (refill_buffer(ctx) <= 0)
		return -1;

	*p = *ctx->head++;

	if (*p == '\n')
	{
	    *p = 0;
	    break;
	}
	p++;
	len++;
    }

    return len;
}

static int read_response(CvsServerCtx * ctx, const char * str)
{
    /* FIXME: more than 1 char at a time */
    char resp[BUFSIZ];

    if (read_line(ctx, resp) < 0)
	return 0;

    debug(DEBUG_TCP, "response '%s' read", resp);

    return (strcmp(resp, str) == 0);
}

static void ctx_to_fp(CvsServerCtx * ctx, FILE * fp)
{
    char line[BUFSIZ];

    while (1)
    {
	read_line(ctx, line);
	debug(DEBUG_TCP, "ctx_to_fp: %s", line);
	if (memcmp(line, "M ", 2) == 0)
	{
	    if (fp)
		fprintf(fp, "%s\n", line + 2);
	}
	else if (memcmp(line, "E ", 2) == 0)
	{
	    debug(DEBUG_APPMSG1, "%s", line + 2);
	}
	else if (strncmp(line, "ok", 2) == 0 || strncmp(line, "error", 5) == 0)
	{
	    break;
	}
    }

    if (fp)
	fflush(fp);
}

void cvs_rdiff(CvsServerCtx * ctx, 
	       const char * rep, const char * file, 
	       const char * rev1, const char * rev2)
{
    /* NOTE: opts are ignored for rdiff, '-u' is always used */

    send_string(ctx, "Argument -u\n");
    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev1);
    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev2);
    send_string(ctx, "Argument %s%s\n", rep, file);
    send_string(ctx, "rdiff\n");

    ctx_to_fp(ctx, stdout);
}

void cvs_rupdate(CvsServerCtx * ctx, const char * rep, const char * file, const char * rev, int create, const char * opts)
{
    FILE * fp;
    char cmdbuff[BUFSIZ];
    
    snprintf(cmdbuff, BUFSIZ, "diff %s %s /dev/null %s | sed -e '%s s|^\\([+-][+-][+-]\\) -|\\1 %s/%s|g'",
	     opts, create?"":"-", create?"-":"", create?"2":"1", rep, file);

    debug(DEBUG_TCP, "cmdbuff: %s", cmdbuff);

    if (!(fp = popen(cmdbuff, "w")))
    {
	debug(DEBUG_APPERROR, "cvs_direct: popen for diff failed: %s", cmdbuff);
	exit(1);
    }

    send_string(ctx, "Argument -p\n");
    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev);
    send_string(ctx, "Argument %s/%s\n", rep, file);
    send_string(ctx, "co\n");

    ctx_to_fp(ctx, fp);

    pclose(fp);
}

static int parse_patch_arg(char * arg, char ** str)
{
    char *tok, *tok2 = "";
    tok = strsep(str, " ");
    if (!tok)
	return 0;

    if (!*tok == '-')
    {
	debug(DEBUG_APPERROR, "diff_opts parse error: no '-' starting argument: %s", *str);
	return 0;
    }
    
    /* if it's not 'long format' argument, we can process it efficiently */
    if (tok[1] == '-')
    {
	debug(DEBUG_APPERROR, "diff_opts parse_error: long format args not supported");
	return 0;
    }

    /* see if command wants two args and they're separated by ' ' */
    if (tok[2] == 0 && strchr("BdDFgiorVxYz", tok[1]))
    {
	tok2 = strsep(str, " ");
	if (!tok2)
	{
	    debug(DEBUG_APPERROR, "diff_opts parse_error: argument %s requires two arguments", tok);
	    return 0;
	}
    }
    
    snprintf(arg, 32, "%s%s", tok, tok2);
    return 1;
}

void cvs_diff(CvsServerCtx * ctx, 
	       const char * rep, const char * file, 
	       const char * rev1, const char * rev2, const char * opts)
{
    char argstr[BUFSIZ], *p = argstr;
    char arg[32];
    char file_buff[PATH_MAX], *basename;

    strzncpy(argstr, opts, BUFSIZ);
    while (parse_patch_arg(arg, &p))
	send_string(ctx, "Argument %s\n", arg);

    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev1);
    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev2);

    /* 
     * we need to separate the 'basename' of file in order to 
     * generate the Directory directive(s)
     */
    strzncpy(file_buff, file, PATH_MAX);
    if ((basename = strrchr(file_buff, '/')))
    {
	*basename = 0;
	send_string(ctx, "Directory %s/%s\n", rep, file_buff);
	send_string(ctx, "%s/%s/%s\n", ctx->root, rep, file_buff);
    }
    else
    {
	send_string(ctx, "Directory %s\n", rep, file_buff);
	send_string(ctx, "%s/%s\n", ctx->root, rep);
    }

    send_string(ctx, "Directory .\n");
    send_string(ctx, "%s\n", ctx->root);
    send_string(ctx, "Argument %s/%s\n", rep, file);
    send_string(ctx, "diff\n");

    ctx_to_fp(ctx, stdout);
}

/*
 * FIXME: the design of this sucks.  It was originally designed to fork a subprocess
 * which read the cvs response and send it back through a pipe the main process,
 * which fdopen(3)ed the other end, and juts used regular fgets.  This however
 * didn't work because the reads of compressed data in the child process altered
 * the compression state, and there was no way to resynchronize that state with
 * the parent process.  We could use threads...
 */
CvsRlog * cvs_rlog_open(CvsServerCtx * ctx, const char * rep, const char * date_str)
{
    CvsRlog * cvsrlog;

    cvsrlog = calloc(1, sizeof(*cvsrlog));
    if (!cvsrlog)
    {
	debug(DEBUG_SYSERROR, "cvs_rlog_open: calloc failed");
	exit(1);
    }
    cvsrlog->csctx = ctx;
    cvsrlog->flags = CRLOGF_CVSDIRECT;

    /* note: use of the date_str is handled in a non-standard, cvsps specific way */
    if (date_str && date_str[0])
    {
	send_string(ctx, "Argument -d\n", rep);
	send_string(ctx, "Argument %s<1 Jan 2038 05:00:00 -0000\n", date_str);
	send_string(ctx, "Argument -d\n", rep);
	send_string(ctx, "Argument %s\n", date_str);
    }

    send_string(ctx, "Argument %s\n", rep);
    send_string(ctx, "rlog\n");

    /*
     * FIXME: is it possible to create a 'fake' FILE * whose 'refill'
     * function is below?
     */
    return cvsrlog;
}

char * cvs_rlog_fgets(char * buff, int buflen, CvsRlog * cvsrlog)
{
    char lbuff[BUFSIZ];
    int n, len;

    assert(cvsrlog->flags & CRLOGF_CVSDIRECT);

    len = read_line(cvsrlog->csctx, lbuff);
    debug(DEBUG_TCP, "cvs_direct: rlog: read %s", lbuff);

    if (memcmp(lbuff, "M ", 2) == 0 || memcmp(lbuff, "LOGM ", 5) == 0)
    {
	if ('L' == lbuff[0])
	{
	    n = 5;
	    CRLOG_SET_LOGM(cvsrlog);
	}
	else
	{
	    n = 2;
	    CRLOG_CLR_LOGM(cvsrlog);
	}
	if (buflen < len - n) {
	    fprintf(stderr, "****WARNING**** rlog buffer len(=%d) > "
		"buflen(=%d)\n", len - n, buflen);
	    len = buflen;
	}
	memcpy(buff, lbuff + n, len - n);
	buff[len - n ] = '\n';
	buff[len - n + 1 ] = 0;
    }
    else if (memcmp(lbuff, "E ", 2) == 0)
    {
	debug(DEBUG_APPMSG1, "%s", lbuff + 2);
    }
    else if (strcmp(lbuff, "ok") == 0 ||strcmp(lbuff, "error") == 0)
    {
	debug(DEBUG_TCP, "cvs_direct: rlog: got command completion");
	return NULL;
    }

    return buff;
}

void cvs_rlog_close(CvsRlog * cvsrlog)
{
    assert(cvsrlog->flags & CRLOGF_CVSDIRECT);
    free(cvsrlog);
}

void cvs_version(CvsServerCtx * ctx, char * client_version, char * server_version)
{
    char lbuff[BUFSIZ];
    strcpy(client_version, "Client: Concurrent Versions System (CVS) 99.99.99 (client/server) cvs-direct");
    send_string(ctx, "version\n");
    read_line(ctx, lbuff);
    if (memcmp(lbuff, "M ", 2) == 0)
	sprintf(server_version, "Server: %s", lbuff + 2);
    else
	debug(DEBUG_APPERROR, "cvs_direct: didn't read version: %s", lbuff);
    
    read_line(ctx, lbuff);
    if (strcmp(lbuff, "ok") != 0)
	debug(DEBUG_APPERROR, "cvs_direct: protocol error reading version");

    debug(DEBUG_TCP, "cvs_direct: client version %s", client_version);
    debug(DEBUG_TCP, "cvs_direct: server version %s", server_version);
}
