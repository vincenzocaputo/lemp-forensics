#    Copyright (c) 2020, Vincenzo Caputo
#
#       All rights reserved.
#
#       Redistribution and use in source and binary forms, with or without modification,
#       are permitted provided that the following conditions are met:
#
#       * Redistributions of source code must retain the above copyright notice, this
#         list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above copyright notice,
#         this list of conditions and the following disclaimer in the documentation
#         and/or other materials provided with the distribution.
#       * The names of the contributors may not be used to endorse or promote products
#         derived from this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#       AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#       ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#       LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#       SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#       CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#       OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""Extracts HTTP latest requests received by nginx"""

__author__ = "Vincenzo Caputo"

from rekall import obj
from rekall.plugins.overlays import basic
from rekall.plugins.linux import heap_analysis
import os
import re

"""
nginx plugin implementation.
It extracts latest HTTP requests received by the web server.
"""
class Nginx(heap_analysis.HeapAnalysis):

    name = "nginx"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="task", hidden=True),
        dict(name="variable", width=25),
        dict(name="value", width=60)
    ]

    HTTP_SIGNATURE = '\x48\x54\x54\x50\x00\x00\x00\x00'

    def __init__(self, **kwargs):
        super(Nginx, self).__init__(**kwargs)
        self._nginx_profile = None

    """ 
    Extracts string from ngx_str_t data structure
    """
    def get_string(self, ngx_str_t):
        return ngx_str_t.data[:ngx_str_t.len]

    def collect(self):
        for task in self.filter_processes():
            if not self.init_for_task(task):
                continue

            self._nginx_profile = NginxProfile(session=self.session)

            connection_size = self._nginx_profile.get_obj_size(
                                                    'ngx_connection_t')
            http_request_size = self._nginx_profile.get_obj_size(
                                                    'ngx_http_request_t')
            

            output_dict = []

            # Search chunks containing ngx_http_request_t structure
            result = self.search_chunks_for_needle(search_string=str(
                                                    self.HTTP_SIGNATURE))

            active_conns = []
            for chunk in list(result.keys()):

                # The structure may not be at the beginning of the chunk
                offset = result[chunk][b'HTTP\x00\x00\x00\x00'].pop()

                ngx_http_request_t = self._nginx_profile.ngx_http_request_t(
                                            offset=offset, vm=self.process_as)

                # The chunk must be enough big to contain the structure                          
                if offset+http_request_size > ngx_http_request_t.v()+chunk.chunksize():
                    continue
                
                # The connection field must contain a pointer to a valid heap memory location
                if self.is_address_part_of_heap(ngx_http_request_t.connection.v()) \
                   is False:
                    continue

                # Gain IP address of client
                ip_address = self.get_string(
                                    ngx_http_request_t.connection.addr_text)
                output_dict.append(["Client_address", ip_address])

                # Add current connection to connections list
                active_conns.append(ngx_http_request_t.connection)

                # Gain number of requests received in this connection
                request_count = ngx_http_request_t.connection.requests
                output_dict.append(["Requests counter", request_count])

                # Get timestamp of request
                timestamp = self.profile.UnixTimeStamp(
                                            value=ngx_http_request_t.start_sec)
                output_dict.append(["Timestamp", timestamp])

                # Get HTTP method
                method_code = ngx_http_request_t.method
                method = self._nginx_profile.get_http_method(method_code)
                output_dict.append(["HTTP_method", method])

                # Get HTTP version
                uri = ''
                http_version_code = ngx_http_request_t.http_version
                http_version = self._nginx_profile.get_http_version(
                                                            http_version_code)
                output_dict.append(["HTTP version", http_version])

                # Get requested URI
                uri = ''
                uri_addr = ngx_http_request_t.uri.data.v()
                for ch in self.get_chunks_for_addresses({uri_addr}):
                    uri = ch.get_chunk_data(length=ngx_http_request_t.uri.len,
                                            offset=uri_addr - ch.v())
                output_dict.append(["URI", uri])

                # Get request's arguments
                args = ''
                args_addr = ngx_http_request_t.args.data.v()
                for ch in self.get_chunks_for_addresses({uri_addr}):
                    args = ch.get_chunk_data(
                                            length=ngx_http_request_t.args.len,
                                            offset=args_addr - ch.v())
                output_dict.append(["args", args])

                # Get response's status code
                status_code = ngx_http_request_t.headers_out.status
                output_dict.append(["status code", status_code])

                # Get response's status
                status = ngx_http_request_t.headers_out.status_line.data
                output_dict.append(["status", status])

                # Get header fields of the request
                in_fields_list = ngx_http_request_t.headers_in.fields_list
                for field in in_fields_list:
                    # Check if the field is not empty
                    if isinstance(field.elt_key.data, obj.NoneObject) is False:
                        output_dict.append([field.elt_key.data,
                                            field.elt_value.data])
                        request_addr = field.elt_value.data.v()

                        # Save the chunk containing the raw request
                        for ch in self.get_chunks_for_addresses({request_addr
                                                                 }):
                            filename = "nginx-http-request-" + str(hex(ch.v()))
                            if os.path.exists(filename):
                                continue
                            data = ch.get_chunk_data()
                            with self.session.GetRenderer().open(
                                    directory=".", filename=filename,
                                    mode='wb') as output_file:
                                output_file.write(data)

                # Get header fields of the response
                out_fields_list = ngx_http_request_t.headers_out.fields_list
                for field in out_fields_list:
                    # Check if the field is not empty
                    if isinstance(field.elt_key.data, obj.NoneObject) is False:
                        output_dict.append([field.elt_key.data,
                                            field.elt_value.data])
                        response_addr = field.elt_value.data.v()

                        # Save the chunk containing the raw response
                        for ch in self.get_chunks_for_addresses(
                            {response_addr}):
                            filename = "nginx-http-response-" + str(hex(
                                ch.v()))
                            if os.path.exists(filename):
                                continue
                            data = ch.get_chunk_data()
                            with self.session.GetRenderer().open(
                                    directory=".", filename=filename,
                                    mode='wb') as output_file:
                                output_file.write(data)

                output_dict.append(["=" * 25, "=" * 60])

                # Browse connections list
                for conn_addr in active_conns:
                    offset = 16
                    # Find the chunk containing active connections
                    conn_array = next(iter(self.get_chunks_for_addresses(
                                                            [conn_addr.v()])))
                    base_addr = conn_array.v()
                    # Scan the list
                    while offset < conn_array.chunksize():
                        # Avoid already evaluated connection
                        if base_addr + offset not in active_conns:
                            connection = self._nginx_profile.ngx_connection_t(
                                offset=base_addr + offset, vm=self.process_as)
                            # Get IP address and number of requests from
                            # connection structure
                            if connection.addr_text.len != 0:
                                ip = self.get_string(connection.addr_text)
                                output_dict.append(["Address", ip])

                                output_dict.append(
                                    ["Requests counter", connection.requests])
                                output_dict.append(["=" * 25, "=" * 60])
                        offset += connection_size

            for value in output_dict:
                yield dict(task=task, variable=value[0], value=value[1])


class NginxProfile(basic.ProfileLP64, basic.BasicClasses):
    __abstract = True

    """ 
    This structure contains header fields of a HTTP request
    """
    ngx_http_headers_in_t_vtype_64 = {
        "ngx_http_headers_in_t": [432, {
            "headers": [0, ["void"]],
            "fields_list": [56, ["Array", {
                    "count": 35,
                    "target": "Pointer",
                    "target_args": {
                        "target": "ngx_table_elt_t",
                        "target_args": None
                    }
                }
            ]],
        }]
    }

    """
    This structure contains header fields of a HTTP response
    """
    ngx_http_headers_out_t_vtype_64 = {
        "ngx_http_headers_out_t": [408, {
            "status": [112, ["long int"]],
            "status_line": [120, ["ngx_str_t"]],
            "fields_list": [136,["Array", {
                    "count": 12,
                    "target": "Pointer",
                    "target_args": {
                        "target": "ngx_table_elt_t",
                        "target_args": None
                    }
                }
            ]],
        }]
    }

    """
    This structure contains information about a HTTP request
    """
    ngx_http_request_t_vtype_64 = {
        "ngx_http_request_t": [1456, {
            "signature": [0, ["long int"]],
            "connection": [8, ["Pointer", {
                "target": "ngx_connection_t"
            }]],
            "headers_in": [104, ["ngx_http_headers_in_t"]],
            "headers_out": [536, ["ngx_http_headers_out_t"]],
            "start_sec": [960, ["long int"]],
            "method": [976, ["long int"]],
            "http_version": [984, ["long int"]],
            "uri": [1008, ["ngx_str_t"]],
            "args": [1024, ["ngx_str_t"]],
        }]
    }

    """
    This structure contains information about an active connection
    """
    ngx_connection_t_vtype_64 = {
        "ngx_connection_t": [232, {
            "addr_text": [120, ["ngx_str_t"]],
            "requests": [208, ["long int"]]
        }]
    }

    """
    This structure creates a hash table. 
    It is used to manage headers field of the HTTP messages.
    """
    ngx_table_elt_t_vtype_64 = {
        "ngx_table_elt_t": [48, {
            "hash": [0, ["long int"]],
            "elt_key": [8, ["ngx_str_t"]],
            "elt_value": [24, ["ngx_str_t"]],
            "lowcase_key": [40, ["Pointer", {
                "target": "String"
            }]]
        }]
    }

    """
    This structure contains a string with its length
    """
    ngx_str_t_vtype_64 = {
        "ngx_str_t": [16, {
            "len": [0, ["long int"]],
            "data": [8, ["Pointer", {
                "target": "String"
            }]],
        }]
    }

    version_dict = {
        '0': [
            ngx_http_headers_in_t_vtype_64, ngx_http_headers_out_t_vtype_64,
            ngx_http_request_t_vtype_64, ngx_str_t_vtype_64,
            ngx_connection_t_vtype_64, ngx_table_elt_t_vtype_64,
        ]
    }

    def __init__(self, version=None, **kwargs):
        super(NginxProfile, self).__init__(**kwargs)

        profile = dict()

        for vtypes in self.version_dict['0']:
            profile.update(vtypes)

        self.add_types(profile)

    def get_http_method(self, code):
        method_switcher = {
            0x0001: "UNKNOWN",
            0x0002: "GET",
            0x0004: "HEAD",
            0x0008: "POST",
            0x0010: "PUT",
            0x0020: "DELETE",
            0x0040: "MKCOL",
            0x0080: "COPY",
            0x0100: "MOVE",
            0x0200: "OPTIONS",
            0x0400: "PROPFIND",
            0x0800: "PROPPATCH",
            0x1000: "LOCK",
            0x2000: "UNLOCK",
            0x4000: "PATCH",
            0x8000: "TRACE"
        }
        return method_switcher.get(code)

    def get_http_version(self, code):
        method_switcher = {
            9: "HTTP 0.9",
            1000: "HTTP 1.0",
            1001: "HTTP 1.1",
            2000: "HTTP 2.0"
        }
        return method_switcher.get(code)
