/*
 * Copyright (c) 2016-2018, OARC, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

#include "dnscap_common.h"

#include "dnstap.pb-c.h"

static logerr_t*   logerr;

output_t dnstap_output;

void dnstap_usage()
{
}

void dnstap_getopt(int* argc, char** argv[])
{
}

int dnstap_start(logerr_t* a_logerr)
{
    logerr = a_logerr;
    return 0;
}

void dnstap_stop()
{
}

int dnstap_open(my_bpftimeval ts)
{
    return 0;
}

int dnstap_close(my_bpftimeval ts)
{
    return 0;
}

#define DNSTAP_INITIAL_BUF_SIZE		256

int num = 0;

#include <tinycbor/cbor.h>

void dnstap_output(const char* descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, const unsigned olen,
    const u_char* payload, const unsigned payloadlen)
{
    static char *fakezone = "fakezone.com";
    size_t n;


    if (num)
        return;

    if (0) {
        CborEncoder root, d, m;
        uint8_t buf[64*1024];
        int err = 0;

        for (n=1e7; n--;) {
            cbor_encoder_init(&root, buf, sizeof(buf), 0);
            err |= cbor_encoder_create_map(&root, &d, 2);
            err |= cbor_encode_simple_value(&d, 15);
            err |= cbor_encode_int(&d, 1);
            err |= cbor_encode_simple_value(&d, 14);
            err |= cbor_encoder_create_map(&d, &m, 9);
            err |= cbor_encode_simple_value(&m, 1);
            err |= cbor_encode_int(&m, 1);
            err |= cbor_encode_simple_value(&m, 2);
            err |= cbor_encode_int(&m, 1);
            err |= cbor_encode_simple_value(&m, 3);
            err |= cbor_encode_int(&m, 1);
            err |= cbor_encode_simple_value(&m, 4);
            err |= cbor_encode_byte_string(&m, (uint8_t*)&from.u.a4, 4);
            err |= cbor_encode_simple_value(&m, 6);
            err |= cbor_encode_int(&m, sport);
            err |= cbor_encode_simple_value(&m, 8);
            err |= cbor_encode_int(&m, ts.tv_sec);
            err |= cbor_encode_simple_value(&m, 9);
            err |= cbor_encode_int(&m, ts.tv_usec * 1000);
            err |= cbor_encode_simple_value(&m, 10);
            err |= cbor_encode_byte_string(&m, payload, payloadlen);
            err |= cbor_encode_simple_value(&m, 11);
            err |= cbor_encode_text_string(&m, fakezone, sizeof(fakezone));
            err |= cbor_encoder_close_container(&d, &m);
            err |= cbor_encoder_close_container(&root, &d);
        }
    }

    if (1) {
        Dnstap__Dnstap d;
        Dnstap__Message m;
    	ProtobufCBufferSimple sbuf;

        memset(&sbuf, 0, sizeof(sbuf));
        sbuf.base.append = protobuf_c_buffer_simple_append;
        sbuf.len = 0;
        sbuf.alloced = DNSTAP_INITIAL_BUF_SIZE;
        sbuf.data = malloc(sbuf.alloced);
        sbuf.must_free_data = 1;

        memset(&d, 0, sizeof(Dnstap__Dnstap));
        memset(&m, 0, sizeof(Dnstap__Message));

        for (n=1e7; n--;) {
            d.base.descriptor = &dnstap__dnstap__descriptor;
        	m.base.descriptor = &dnstap__message__descriptor;
        	d.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
        	d.message = &m;
        	m.type = DNSTAP__MESSAGE__TYPE__AUTH_QUERY;

            m.query_zone.data = fakezone;
            m.query_zone.len = sizeof(fakezone);
            m.has_query_zone = 1;

            m.response_time_sec = ts.tv_sec;
            m.has_response_time_sec = 1;
            m.response_time_nsec = ts.tv_usec * 1000;
            m.has_response_time_nsec = 1;

            m.response_message.len = payloadlen;
            m.response_message.data = payload;
            m.has_response_message = 1;

            m.socket_family = DNSTAP__SOCKET_FAMILY__INET;
            m.has_socket_family = 1;
            m.query_address.data = &from.u.a4;
            m.query_address.len = 4;
            m.has_query_address = 1;
            m.query_port = sport;
            m.has_query_port = 1;


            sbuf.len = 0;

        	dnstap__dnstap__pack_to_buffer(&d, (ProtobufCBuffer *) &sbuf);
        }

        free(sbuf.data);
    }

    num++;
}
