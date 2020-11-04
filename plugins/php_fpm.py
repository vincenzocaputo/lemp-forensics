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
"""Extracts php-fpm history data"""

__author__ = "Vincenzo Caputo"

from rekall.plugins.overlays import basic
from rekall.plugins.linux import heap_analysis
from rekall import obj
import re

""" 
php-fpm plugin implementantion.
It extracts information about PHP script execution requests.
"""
class PhpFpm(heap_analysis.HeapAnalysis):

    name = "php-fpm"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="task", hidden=True),
        dict(name="variable", width=20),
        dict(name="value", width=150)
    ]

    def __init__(self, **kwargs):
        super(PhpFpm, self).__init__(**kwargs)
        self._php_fpm_profile = None

    def collect(self):
        for task in self.filter_processes():
            if not self.init_for_task(task):
                continue

            self._php_fpm_profile = PhpFpmProfile(session=self.session)

            data_offset = self.profile.get_obj_offset("malloc_chunk", "fd")

            chunks_dict = dict()

            # Search chunks that contain a _fcgi_hash_buckets struct

            # The struct has size of 6160 bytes
            chunk_size = self._php_fpm_profile.get_obj_size('fcgi_hash_buckets')

            # Get aligned size of chunk (i.e.: 6176 bytes)
            chunk_size = self.get_aligned_size(chunk_size)

            output_dict = []

            for chunk in self.get_all_chunks():
                chunks_dict[chunk.v() + data_offset] = chunk

            for chunk in chunks_dict.values():

                if chunk.chunksize() == chunk_size:
                    hash_buckets = self._php_fpm_profile.fcgi_hash_buckets(
                        offset=chunk.v() + data_offset, vm=self.process_as)

                    # Gain array of hash_buckets
                    hash_array = hash_buckets.data
                    hash_dict = dict()
                    for hash_bucket in hash_array:
                        hash_dict[hash_bucket.v()] = hash_bucket

                    for hash_bucket in hash_dict.values():
                        if hash_bucket.list_next.v() != 0 and \
                        hash_bucket.list_next not in hash_dict:
                            continue
                        if hash_bucket.var_len <= 0 or hash_bucket.val_len <= 0:
                            continue
                        # If there is a valid variable name, take the associated value
                        if str(hash_bucket.var).isascii() and str(hash_bucket.val).isascii():                            
                            output_dict.append([
                                hash_bucket.var[:hash_bucket.var_len],
                                hash_bucket.val[:hash_bucket.val_len]
                            ])

            for value in output_dict:
                yield dict(task=task, variable=value[0], value=value[1])


"""
php-fpm-ls plugin implementation.
It retrieves the list of the latest PHP scripts executed by the web server.
"""
class PhpFpmList(heap_analysis.HeapAnalysis):

    name = "php-fpm-ls"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="task", hidden=True),
        dict(name="path", width=65),
        dict(name="realpath", width=65),
        dict(name="uploaded", width=21),
        dict(name="expiration", width=21)
    ]

    def __init__(self, **kwargs):
        super(PhpFpmList, self).__init__(**kwargs)
        self._php_fpm_profile = None

    def collect(self):
        for task in self.filter_processes():
            if not self.init_for_task(task):
                continue

            self._php_fpm_profile = PhpFpmProfile(session=self.session)

            data_offset = self.profile.get_obj_offset("malloc_chunk", "fd")

            chunks_dict = []

            output_dict = []

            struct_size = self._php_fpm_profile.get_obj_size(
                                                        'realpath_cache_bucket')
            # Gain all chunks from heap memory
            for chunk in self.get_all_chunks():
                chunks_dict.append(chunk)

            for chunk in chunks_dict:
                # The chunk should have a minimum size of 48 bytes
                if chunk.chunksize() >= struct_size:
                    realpath_cache_bucket = self._php_fpm_profile.realpath_cache_bucket(
                        offset=chunk.v() + data_offset, vm=self.process_as)

                    # Check if path field contains a pointer to the chunk itself
                    # The path string must immediately follow the structure
                    if realpath_cache_bucket.path.v()   \
                       != realpath_cache_bucket.v() + 48:
                        continue

                    # If path and realpath are the same, 
                    # the associated strings must have the same length
                    if realpath_cache_bucket.path.v()   \
                       == realpath_cache_bucket.realpath.v():
                        if realpath_cache_bucket.path_len \
                           != realpath_cache_bucket.realpath_len:
                            continue
                        
                        # In this case, the chunk size must be equal to
                        # the size of the struct plus the length of the path string
                        if chunk.chunksize() != self.get_aligned_size(
                                48 + realpath_cache_bucket.path_len + 1):
                            continue
                    else:
                        # The realpath string must immediately follow 
                        # the path string
                        if realpath_cache_bucket.realpath.v() \
                           != realpath_cache_bucket.v() + 48 + \
                              realpath_cache_bucket.path_len + 1:
                            continue

                        # In this case, the chunk size must be equal to
                        # the size of the struct plus the length of the two path strings
                        if chunk.chunksize() != self.get_aligned_size(
                                48 + realpath_cache_bucket.path_len +
                                realpath_cache_bucket.realpath_len + 2):
                            continue

                    output_dict.append([
                        realpath_cache_bucket.path[:realpath_cache_bucket.
                                                   path_len],
                        realpath_cache_bucket.realpath[:realpath_cache_bucket.realpath_len],
                        self.profile.UnixTimeStamp(
                            value=realpath_cache_bucket.expires -
                            self._php_fpm_profile.REALPATH_CACHE_TTL),
                        self.profile.UnixTimeStamp(
                            value=realpath_cache_bucket.expires)
                    ])

            for value in output_dict:
                yield dict(task=task,
                           path=value[0],
                           realpath=value[1],
                           uploaded=value[2],
                           expiration=value[3])


class PhpFpmProfile(basic.ProfileLP64, basic.BasicClasses):
    __abstract = True

    FCGI_HASH_TABLE_SIZE = 128
    REALPATH_CACHE_TTL = 120

    """
    This structure creates a hash table, used by php-fpm to 
    manage information about PHP script execution requests.
    """
    fcgi_hash_buckets_vtype_64 = {
        "fcgi_hash_buckets": [6160, {
            "idx": [0, ["int"]],
            "next": [8, ["Pointer", {
                "target": "_fcgi_hash_buckets"
            }]],
            "data": [16,["Array", {
                    "count": FCGI_HASH_TABLE_SIZE,
                    "target": "fcgi_hash_bucket",
                    "target_args": None
                }]
            ]
        }]
    }
    
    """
    This structure represents a key-value pair of the hash table.
    Each key-value pair describes a specific attribute of the request.
    """
    fcgi_hash_bucket_vtype_64 = {
        "fcgi_hash_bucket": [48, {
            "hash_value": [0, ["unsigned int"]],
            "var_len": [4, ["unsigned int"]],
            "var": [8, ["Pointer", {
                "target": "String"
            }]],
            "val_len": [16, ["unsigned int"]],
            "val": [24, ["Pointer", {
                "target": "String"
            }]],
            "next": [32, ["Pointer", {
                "target": "fcgi_hash_bucket"
            }]],
            "list_next": [40, ["Pointer", {
                "target": "fcgi_hash_bucket"
            }]]
        }]
    }

    """
    This structure contains informations about system paths 
    of executed PHP scripts
    """
    realpath_cache_bucket_vtype_64 = {
        "realpath_cache_bucket": [48, {
            "key": [0, ["long int"]],
            "path": [8, ["Pointer", {
                "target": "String"
            }]],
            "realpath": [16, ["Pointer", {
                "target": "String"
            }]],
            "next": [24, ["Pointer", {
                "target": "realpath_cache_bucket"
            }]],
            "expires": [32, ["long int"]],
            "path_len": [40, ["short int"]],
            "realpath_len": [42, ["short int"]],
            "is_dir": [44, ["int"]]
        }]
    }

    version_dict = {
        '72': [
            fcgi_hash_buckets_vtype_64, fcgi_hash_bucket_vtype_64,
            realpath_cache_bucket_vtype_64
        ]
    }

    def __init__(self, version=None, **kwargs):
        super(PhpFpmProfile, self).__init__(**kwargs)

        profile = dict()

        for vtypes in self.version_dict['72']:
            profile.update(vtypes)

        self.add_types(profile)
