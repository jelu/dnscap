#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "../../dnscap_common.h"


#define MY_GET16(s, cp) do { \
  register const u_char *t_cp = (const u_char *)(cp); \
  (s) = ((u_int16_t)t_cp[0] << 8) \
      | ((u_int16_t)t_cp[1]) \
      ; \
  (cp) += INT16SZ; \
} while (0)

#define MY_GET32(l, cp) do { \
  register const u_char *t_cp = (const u_char *)(cp); \
  (l) = ((u_int32_t)t_cp[0] << 24) \
      | ((u_int32_t)t_cp[1] << 16) \
      | ((u_int32_t)t_cp[2] << 8) \
      | ((u_int32_t)t_cp[3]) \
      ; \
  (cp) += INT32SZ; \
} while (0)

static void dump_dns_sect_csv(ns_msg *, const ns_sect, const my_bpftimeval *ts, const iaddr *from);
static void dump_dns_rr_csv(ns_msg *, ns_rr *, ns_sect, const my_bpftimeval *ts, const iaddr *from);

static logerr_t *logerr;
static int opt_f = 0;
static const char *opt_o = 0;
static FILE *out = 0;

output_t csvout_output;

void
csvout_usage()
{
	fprintf(stderr,
		"\ncsvout.so options:\n"
		"\t-f         flag option\n"
		"\t-o <arg>   output file name\n"
		);
}

void
csvout_getopt(int *argc, char **argv[])
{
	/*
	 * The "getopt" function will be called from the parent to
	 * process plugin options.
	 */
	int c;
	while ((c = getopt(*argc, *argv, "fo:")) != EOF) {
		switch(c) {
		case 'f':
			opt_f = 1;
			break;
		case 'o':
			opt_o = strdup(optarg);
			break;
		default:
			csvout_usage();
			exit(1);
		}
	}
}

int
csvout_start(logerr_t *a_logerr)
{
	/*
	 * The "start" function is called once, when the program
	 * starts.  It is used to initialize the plugin.  If the
	 * plugin wants to write debugging and or error messages,
	 * it should save the a_logerr pointer passed from the
	 * parent code.
	 */
	logerr = a_logerr;
	if (opt_o) {
		out = fopen(opt_o, "w");
		if (0 == out) {
			logerr("%s: %s\n", opt_o, strerror(errno));
			exit(1);
		}
	} else {
		out = stdout;
	}
	return 0;
}

void
csvout_stop()
{
	/*
	 * The "start" function is called once, when the program
	 * is exiting normally.  It might be used to clean up state,
	 * free memory, etc.
	 */
	fclose(out);
}

int
csvout_open(my_bpftimeval ts)
{
	/*
	 * The "open" function is called at the start of each
	 * collection interval, which might be based on a period
	 * of time or a number of packets.  In the original code,
	 * this is where we opened an output pcap file.
	 */
	return 0;
}

int
csvout_close(my_bpftimeval ts)
{
	/*
	 * The "close" function is called at the end of each
	 * collection interval, which might be based on a period
	 * of time or on a number of packets.  In the original code
	 * this is where we closed an output pcap file.
	 */
	return 0;
}

static const char *
ia_str(iaddr ia) {
        static char ret[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

        (void) inet_ntop(ia.af, &ia.u, ret, sizeof ret);
        return (ret);
}

void
csvout_output(const char *descr, iaddr from, iaddr to, uint8_t proto, int isfrag,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char *pkt_copy, unsigned olen,
    const u_char *dnspkt, unsigned dnslen)
{
	/*
	 * IP Stuff
	 */
//	fprintf(out, "%10lu.%06lu", ts.tv_sec, ts.tv_usec);
//	fprintf(out, " %s %hu", ia_str(from), sport);
//	fprintf(out, " %s %hu", ia_str(to), dport);
//	fprintf(out, " %hhu", proto);

	if (dnspkt) {
		ns_msg msg;
//		int qdcount;
//		ns_rr rr;
		ns_initparse(dnspkt, dnslen, &msg);
		/*
		 * DNS Header
		 */
//		fprintf(out, " %u", ns_msg_id(msg));
//		fprintf(out, " %u", ns_msg_getflag(msg, ns_f_opcode));
//		fprintf(out, " %u", ns_msg_getflag(msg, ns_f_rcode));
//		fprintf(out, " |");
//		if (ns_msg_getflag(msg, ns_f_qr)) fprintf(out, "QR|");
//		if (ns_msg_getflag(msg, ns_f_aa)) fprintf(out, "AA|");
//		if (ns_msg_getflag(msg, ns_f_tc)) fprintf(out, "TC|");
//		if (ns_msg_getflag(msg, ns_f_rd)) fprintf(out, "RD|");
//		if (ns_msg_getflag(msg, ns_f_ra)) fprintf(out, "RA|");
//		if (ns_msg_getflag(msg, ns_f_ad)) fprintf(out, "AD|");
//		if (ns_msg_getflag(msg, ns_f_cd)) fprintf(out, "CD|");
		
//		qdcount = ns_msg_count(msg, ns_s_qd);
//		if (qdcount > 0 && 0 == ns_parserr(&msg, ns_s_qd, 0, &rr)) {
//			fprintf (out, " %s %s %s",
//				p_class(ns_rr_class(rr)),
//				p_type(ns_rr_type(rr)),
//				ns_rr_name(rr));
//		}

    dump_dns_sect_csv(&msg, ns_s_an, &ts, &from);
//    dump_dns_sect_csv(&msg, ns_s_ns, &ts, &from);
//    dump_dns_sect_csv(&msg, ns_s_ar, &ts, &from);
  }
}

static void
dump_dns_sect_csv(ns_msg *msg, const ns_sect sect, const my_bpftimeval *ts, const iaddr *from) {
	int rrnum, rrmax;
	ns_rr rr;

	rrmax = ns_msg_count(*msg, sect);
	if (rrmax == 0) {
		return;
	}

	for (rrnum = 0; rrnum < rrmax; rrnum++) {
		if (ns_parserr(msg, sect, rrnum, &rr)) {
			fputs(strerror(errno), out);
			return;
		}

    if (sect == ns_s_qd)
      continue;

		dump_dns_rr_csv(msg, &rr, sect, ts, from);
	}
}

static void
dump_dns_rr_csv(ns_msg *msg, ns_rr *rr, ns_sect sect, const my_bpftimeval *ts, const iaddr *from) {
	char buf[NS_MAXDNAME];
	u_int type;
	const u_char *rd;
	u_int32_t soa[5];
	u_int16_t mx;
	int n;

	type = ns_rr_type(*rr);
	rd = ns_rr_rdata(*rr);

	fprintf(out, "%s,%10lu.%06lu,%s,%s,%s,%lu",
    ia_str(*from),
    (*ts).tv_sec,
    (*ts).tv_usec,
		ns_rr_name(*rr),
		p_class(ns_rr_class(*rr)),
		p_type(type),
    (u_long)ns_rr_ttl(*rr));

	switch (type) {
    case ns_t_soa:
      n = ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg),
                 rd, buf, sizeof buf);
      if (n < 0)
        goto error;

      putc(',', out);
      fputs(buf, out);
      rd += n;
      n = ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg),
                 rd, buf, sizeof buf);
      if (n < 0)
        goto error;
      putc(',', out);
      fputs(buf, out);
      rd += n;
      if (ns_msg_end(*msg) - rd < 5*NS_INT32SZ)
        goto error;
      for (n = 0; n < 5; n++)
        MY_GET32(soa[n], rd);
      sprintf(buf, "%u,%u,%u,%u,%u",
        soa[0], soa[1], soa[2], soa[3], soa[4]);
      break;

    case ns_t_a:
      inet_ntop(AF_INET, rd, buf, sizeof buf);
      break;

    case ns_t_aaaa:
      inet_ntop(AF_INET6, rd, buf, sizeof buf);
      break;

    case ns_t_mx:
      MY_GET16(mx, rd);
      fprintf(out, ",%u", mx);
      /* FALLTHROUGH */

    case ns_t_ns:
    case ns_t_ptr:
    case ns_t_cname:
      n = ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg),
                 rd, buf, sizeof buf);
      if (n < 0)
        goto error;
      break;

    case ns_t_txt:
      snprintf(buf, (size_t)rd[0]+1, "%s", rd+1);
      break;

    default:
    error:
      sprintf(buf, "[%u]", ns_rr_rdlen(*rr));
	}

	if (buf[0] != '\0') {
		putc(',', out);
		fputs(buf, out);
	}

  fprintf(out, "%s", "\n");
}

