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
"""Extracts MySQL event history data"""

__author__ = "Vincenzo Caputo"

from rekall.plugins.overlays import basic
from rekall.plugins.linux import heap_analysis
import string
import binascii
import re


class MySqld(heap_analysis.HeapAnalysis):
    _chunks_dict = dict()

    _data_offset = 0
    __args = [
        dict(
            name='force',
            type="Boolean",
            default=False,
            help=("Avoid some controls in order to obtain further information"))
    ]

    def __init__(self, **kwargs):
        super(MySqld, self).__init__(**kwargs)
        self._mysqld_profile = None

    """ 
    Plugin initialization. It loads the profile and retrieves 
    all the chunks from the heap memory.
    returns the result of the iniitalization process.
    """
    def init_collect(self):

        # Find profile
        if self.session.profile.metadata("arch") == 'AMD64':
            self._mysqld_profile = MysqldProfile(session=self.session)
        else:
            return False

        # Get data-offset in chunks
        self._data_offset = self.profile.get_obj_offset("malloc_chunk", "fd")

        # Retrieve all the chunks from the heap memory
        for chunk in self.get_all_chunks():
            # The dictionary uses Data field addresses as keys
            self._chunks_dict[chunk.v() + self._data_offset] = chunk

        return True

    """ 
    Finds the PFS_thread_array object
    returns the list of chunks that potentially contain the PFS_thread_array object.
    """
    def get_pfs_thread_array(self):
        thread_arrays = []
        for chunk in self._chunks_dict.values():
            # Get PFS_thread_array chunk size
            thr_array_chunk_size = self._mysqld_profile.get_obj_size(
                'PFS_thread_array')
            thr_array_chunk_size = self.get_aligned_size(thr_array_chunk_size)

            # The chunk has size 240 bytes and it belongs to main arena
            if chunk.chunksize() \
               != thr_array_chunk_size or chunk.non_main_arena():
                continue

            thread_array = self._mysqld_profile.PFS_thread_array(
                offset=chunk.v() + self._data_offset, vm=self.process_as)

            # The structure must contain the m_ptr pointer
            if thread_array.m_ptr.v() == 0 or not self.is_address_part_of_heap(
                                                    thread_array.m_ptr.v()):
                continue

            # The m_ptr pointer must reference an existing MMAPPED chunk,
            # which contains a thread_array structure
            if (thread_array.m_ptr.v() - self._mysqld_profile.OFFSET) \
               not in self._chunks_dict or \
               not self._chunks_dict[thread_array.m_ptr.v() \
               - self._mysqld_profile.OFFSET].is_mmapped():
                continue

            pointers = thread_array.m_pointers

            valid = True
            # The structure must contain additional 16 pointers to 
            # valid heap memory locations
            for p in pointers:
                if not self.is_address_part_of_heap(p.v()):
                    valid = False
                    break
            if not valid:
                continue

            # The m_statements_history_array pointer must reference
            # an existing MMAPPED chunk
            if (thread_array.m_statements_history_array.v()  \
               - self._mysqld_profile.OFFSET) not in self._chunks_dict or \
               not self._chunks_dict[thread_array.m_statements_history_array.v()\
               - self._mysqld_profile.OFFSET].is_mmapped():
                continue

            thread_arrays.append(thread_array)

        return thread_arrays

    """ 
    Browse thread_array structure in order to gain information about mysql
    user connections.
    returns a dictionary that contains all the active connections of the server.
    """
    def get_user_base_info(self, thread_array):
        thr_chunk_size = self._mysqld_profile.get_obj_size('PFS_thread')

        ptr_addr = thread_array.m_ptr.v()
        ptr_array = self._chunks_dict[ptr_addr - self._mysqld_profile.OFFSET]

        connection_dict = dict()
        while ptr_addr < ptr_array.v() + ptr_array.chunksize():
            # Get a single element of array
            ptr_item = self._mysqld_profile.PFS_thread(offset=ptr_addr,
                                                       vm=self.process_as)
            # Get the username
            username = ptr_item.m_username
            if ptr_item.m_username_length != 0:
                username = username[:ptr_item.m_username_length]
            elif self.plugin_args.force is False:
                username = '---'

            # Get the hostname (or the IP address)
            hostname = ptr_item.m_hostname
            if ptr_item.m_hostname_length != 0:
                hostname = hostname[:ptr_item.m_hostname_length]
            elif self.plugin_args.force is False:
                hostname = '---'

            # Get the groupname
            groupname = ptr_item.m_groupname
            if ptr_item.m_groupname_length != 0:
                groupname = groupname[:ptr_item.m_groupname_length]
            elif self.plugin_args.force is False:
                groupname = '---'

            # Get connection type
            connection_type = self._mysqld_profile.get_connection_type(
                ptr_item.m_connection_type)

            # Get the timestamp of the last event of this connection
            if ptr_item.m_start_time != 0:
                start_time = self.profile.UnixTimeStamp(
                    value=ptr_item.m_start_time)
            else:
                start_time = '---'

            # Get thread ID
            thr_id = ptr_item.m_thread_internal_id

            # If user is still connected, there are further information 
            # about his system
            connect_attrs = ptr_item.m_session_connect_attrs[0:]

            if thr_id not in connection_dict:
                connection_dict[thr_id] = [
                    username, hostname, groupname, connection_type,
                    connect_attrs, start_time
                ]

            ptr_addr += thr_chunk_size

        return connection_dict

    """ 
    Searches information about prepared statements
    return a list of prepared statements
    """
    def get_prep_stmts_array(self):
        prp_stmt_array = []

        prp_stmt_size = self._mysqld_profile.get_obj_size("PFS_prepared_stmt")
        prp_stmt_buffer_size = self._mysqld_profile.PRP_STMT_ARRAY_SIZE \
                                * prp_stmt_size
        prp_stmt_buffer_size = self.get_aligned_size(prp_stmt_buffer_size)

        for chunk in self._chunks_dict.values():

            # The chunk has size 1703952 bytes
            if chunk.chunksize() != prp_stmt_buffer_size:
                continue

            # Get the address of the first element of the array
            array_addr = chunk.v() + self._data_offset

            for i in range(0, self._mysqld_profile.PRP_STMT_ARRAY_SIZE):
                # Gain the index of the current element
                el_index = i * prp_stmt_size
                prp_stmt = self._mysqld_profile.PFS_prepared_stmt(
                    offset=array_addr + el_index, vm=self.process_as)

                prp_stmt_array.append(prp_stmt)

        return prp_stmt_array

""" 
mysqld-hist plugin implementation. 
It extracts MySQL query history.
"""
class MySqldHist(MySqld):
    name = "mysqld-hist"

    table_header = []

    __args = [
        dict(name='errors',
             type="Boolean",
             default=False,
             help=("Print errors details")),
        dict(name='prep_stmts',
             type="Boolean",
             default=False,
             help=("Include prepared statements in the history list"))
    ]

    def __init__(self, **kwargs):
        super(MySqldHist, self).__init__(**kwargs)
        self._mysqld_profile = None
        if self.plugin_args.errors:
            self.table_header = [
                dict(name="divider", type="Divider"),
                dict(name="task", hidden=True),
                dict(name="stmt_id", width=4),
                dict(name="thread_id", width=4),
                dict(name="event_id", width=4),
                dict(name="username", width=14),
                dict(name="host", width=14),
                dict(name="groupname", width=14),
                dict(name="timestamp_start", width=25),
                dict(name="timestamp_end", width=25),
                dict(name="schema_name", width=10),
                dict(name="sql_text", width=50),
                dict(name="rows_affected", width=4),
                dict(name="rows_sent", width=4),
                dict(name="rows_examined", width=4),
                dict(name="message", width=30),
                dict(name="error_no", width=5),
                dict(name="sql_state", width=5),
                dict(name="error_count", width=5)
            ]
        else:
            self.table_header = [
                dict(name="divider", type="Divider"),
                dict(name="task", hidden=True),
                dict(name="stmt_id", align="c", width=4),
                dict(name="thread_id", align="c", width=3),
                dict(name="event_id", width=4),
                dict(name="username", width=8),
                dict(name="host", width=14),
                dict(name="groupname", width=14),
                dict(name="timestamp_start", width=21),
                dict(name="timestamp_end", width=21),
                dict(name="schema_name", width=8),
                dict(name="sql_text", width=30),
                dict(name="rows_affected", align="c", width=3),
                dict(name="rows_sent", align="c", width=3),
                dict(name="rows_examined", align="c", width=3)
            ]

    """ 
    Retrieves the text of prepared statements 
    """
    def get_prepared_statement(self, thread_id, event_id):
        stmt_sql_text = ''
        for prp_stmt in self.prp_stmt_array:
            if prp_stmt.m_stmt_id > 0 and \
               prp_stmt.m_owner_thread_id == thread_id and \
               prp_stmt.m_owner_event_id == event_id:

                stmt_sql_text = prp_stmt.m_sqltext[:prp_stmt.
                                                   m_sqltext_length].decode(
                                                       'utf-8')
                break

        return stmt_sql_text


    def collect(self):
        for task in self.filter_processes():
            if not self.init_for_task(task):
                continue

            if not self.init_collect():
                continue

            if self.plugin_args.prep_stmts:
                self.prp_stmt_array = self.get_prep_stmts_array()

            thread_arrays = self.get_pfs_thread_array()

            stmt_chunk_size = self._mysqld_profile.get_obj_size(
                                                        'PFS_events_statements')

            result_dict = dict()

            count = 0
            for thread_array in thread_arrays:
                # Get info about users
                connection_dict = self.get_user_base_info(thread_array)

                # Get m_statements_history_array start address
                stmts_hist_array_addr = thread_array.m_statements_history_array \
                                                    .v()

                # Get the chunk that contains m_statements_history_array struct
                stmts_hist_array = self._chunks_dict[
                    stmts_hist_array_addr - self._mysqld_profile.OFFSET]

                # Scan the array
                while stmts_hist_array_addr <= (stmts_hist_array.v() +
                                                stmts_hist_array.chunksize()):
                    # Get a single element of array
                    hist_item = self._mysqld_profile.PFS_events_statements(
                        offset=stmts_hist_array_addr, vm=self.process_as)

                    # Check if element is valid
                    if hist_item.m_thread_internal_id != 0:
                        # Get statement ID
                        stmt_id = hist_item.m_statement_id
                        # Get Thread ID
                        thread_id = hist_item.m_thread_internal_id
                        # Get Event ID
                        event_id = hist_item.m_event_id
                        # Retrieve information about the user who sent the query
                        username = '---'
                        hostname = '---'
                        groupname = '---'
                        if thread_id in connection_dict:
                            username = connection_dict[thread_id][0]
                            hostname = connection_dict[thread_id][1]
                            groupname = connection_dict[thread_id][2]

                        # Get timestamp of start and end of execution of the
                        # event. The timestamps are saved in nanoseconds
                        timestamp_start = self.profile.UnixTimeStamp(
                            value=(hist_item.m_timer_start // 1000000000))
                        timestamp_end = self.profile.UnixTimeStamp(
                            value=(hist_item.m_timer_end // 1000000000))

                        # Get the name of the schema
                        schema_name = hist_item.m_schema_name[:hist_item.
                                                        m_schema_name_length]

                        # Get the text of the query
                        sql_len = hist_item.m_sqltext_length
                        sql_text = hist_item.m_sqltext[:sql_len].decode('utf-8')

                        # Get prepared statement definition, if it exists and
                        # prep_stmts option is enabled
                        if self.plugin_args.prep_stmts:
                            prep_stmt = self.get_prepared_statement(
                                thread_id=thread_id, event_id=event_id)

                            if prep_stmt:
                                sql_text = sql_text.replace(
                                    '...', '\'' + prep_stmt + '\'')

                        # Number of rows modified by the query
                        # (e.g.: UPDATE query)
                        rows_affected = hist_item.m_rows_affected
                        # Number of rows sent by server to the client
                        rows_sent = hist_item.m_rows_sent
                        # Number of rows read by the query
                        rows_examined = hist_item.m_rows_examined

                        result_dict[count] = [
                            stmt_id, thread_id, event_id, username, hostname,
                            groupname, timestamp_start, timestamp_end,
                            schema_name, sql_text, rows_affected, rows_sent,
                            rows_examined
                        ]

                        # If errors option is enabled, retrieve information
                        # about errors returned by MySQL
                        if self.plugin_args.errors:
                            # Get SQL message
                            message = hist_item.m_message_text
                            # Get error code
                            error_no = hist_item.m_sql_errno
                            # Get server status
                            sql_state = hist_item.m_sqlstate
                            # Get total number of errors
                            error_count = hist_item.m_error_count

                            result_dict[count] += [
                                message, error_no, sql_state, error_count
                            ]

                        count += 1
                        # If force option is enabled, retrieve old truncated
                        # SQL queries, overwritten by newer ones
                        if self.plugin_args.force:
                            # Retrieve characters until new line
                            sql_text_trunc = hist_item.m_sqltext[0:]
                            sql_text_trunc = sql_text_trunc[0:sql_text_trunc.
                                                            index(b'\x00')]
                            removed_text = ''
                            # If there are more characters than those are belonging
                            # to the new query
                            if len(sql_text_trunc) \
                               > hist_item.m_sqltext_length + 1:
                                # Delete characters belonging to the new query
                                for _ in range(0,
                                                   hist_item.m_sqltext_length):
                                    removed_text += '*'
                                # Extract the remaining characters
                                sql_text_trunc = removed_text + str(
                                    sql_text_trunc[hist_item.
                                                   m_sqltext_length:], 'UTF8')
                                # We can't discover other information about older queries.
                                result_dict[count] = [
                                    0, 0, 0, "---", "---", "---", "---", "---",
                                    "---", sql_text_trunc, '?', '?', '?',
                                    '---', '---', '---', '---'
                                ]
                                count += 1

                    # Go to the next element until the end
                    stmts_hist_array_addr += stmt_chunk_size

            for _, value in sorted(
                    result_dict.items(),
                    key=lambda x: x[1][0]):  # Order by stmt_id
                if self.plugin_args.errors:
                    yield dict(task=task,
                               stmt_id=value[0],
                               thread_id=value[1],
                               event_id=value[2],
                               username=value[3],
                               host=value[4],
                               groupname=value[5],
                               timestamp_start=value[6],
                               timestamp_end=value[7],
                               schema_name=value[8],
                               sql_text=value[9],
                               rows_affected=value[10],
                               rows_sent=value[11],
                               rows_examined=value[12],
                               message=value[13],
                               error_no=value[14],
                               sql_state=value[15],
                               error_count=[16])
                else:
                    yield dict(task=task,
                               stmt_id=value[0],
                               thread_id=value[1],
                               event_id=value[2],
                               username=value[3],
                               host=value[4],
                               groupname=value[5],
                               timestamp_start=value[6],
                               timestamp_end=value[7],
                               schema_name=value[8],
                               sql_text=value[9],
                               rows_affected=value[10],
                               rows_sent=value[11],
                               rows_examined=value[12])

""" 
mysqld-hosts plugin implementation. 
It extracts information on remote hosts connected to the server.
"""
class MySqldHosts(MySqld):
    name = "mysqld-hosts"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="task", hidden=True),
        dict(name="address", width=14),
        dict(name="hostname", width=14),
        dict(name="validated", width=5),
        dict(name="first_seen", width=25),
        dict(name="last_seen", width=25),
        dict(name="first_error_seen", width=25),
        dict(name="last_error_seen", width=25),
        dict(name="connect", width=5),
        dict(name="host_blocked", width=5),
        dict(name="nameinfo_transient", width=5),
        dict(name="nameinfo_permanent", width=5),
        dict(name="format", width=5),
        dict(name="addrinfo_transient", width=5),
        dict(name="addrinfo_permanent", width=5),
        dict(name="FCrDNS", width=5),
        dict(name="host_acl", width=5),
        dict(name="no_auth_plugin", width=5),
        dict(name="auth_plugin", width=5),
        dict(name="handshake", width=5),
        dict(name="proxy_user", width=5),
        dict(name="proxy_user_acl", width=5),
        dict(name="authentication", width=5),
        dict(name="ssl", width=5),
        dict(name="max_user_connection", width=5),
        dict(name="max_user_connection_per_hour", width=5),
        dict(name="default_database", width=5),
        dict(name="init_connect", width=5),
        dict(name="local", width=5)
    ]

    __args = [
        dict(name='errors',
             type="Boolean",
             default=False,
             help=("Includes errors statistics"))
    ]

    def __init__(self, **kwargs):
        super(MySqldHosts, self).__init__(**kwargs)
        self._mysqld_profile = None

    def collect(self):
        for task in self.filter_processes():
            if not self.init_for_task(task):
                continue

            if not self.init_collect():
                continue

            # Get LIST struct size
            list_chunk_size = self._mysqld_profile.get_obj_size('List')
            # Get aligned size of chunk
            list_chunk_size = self.get_aligned_size(list_chunk_size)

            # Get host_entry struct size
            host_entry_chunk_size = self._mysqld_profile.get_obj_size(
                'host_entry')
            # Get aligned size of chunk
            host_entry_chunk_size = self.get_aligned_size(
                host_entry_chunk_size)

            result_dict = []

            for chunk in self._chunks_dict.values():

                # The chunk has size 32 bytes
                if chunk.chunksize() != list_chunk_size:
                    continue

                list_chunk = self._mysqld_profile.List(offset=chunk.v() +
                                                       self._data_offset,
                                                       vm=self.process_as)

                # Get chunk pointers
                pointers = [list_chunk.prev, list_chunk.next, list_chunk.data]

                # The chunk must contain three pointers to valid chunks
                if len(set(pointers) & set(self._chunks_dict)) != len(
                        set(pointers)):
                    continue

                # The element must be in a double-linked list.
                # The next element of the list, must have a pointer to the current
                # element (i.e.: prev pointer)
                if not self._chunks_dict[list_chunk.prev.v()].chunksize() \
                   == list_chunk_size or not list_chunk.prev.next == list_chunk:
                    continue
                # The previous element of the list, must have a pointer to the
                # current element (i.e.: next pointer)
                if not self._chunks_dict[list_chunk.next.v()].chunksize() \
                   == list_chunk_size or not list_chunk.next.prev == list_chunk:
                    continue

                # Data field must reference a valid existing chunk,
                # that contains a Host_entry structure
                if list_chunk.data.v() in self._chunks_dict:
                    host_entry = self._chunks_dict[list_chunk.data.v()]
                    # Check the right size
                    if not host_entry.chunksize() == host_entry_chunk_size:
                        continue

                    host_info = []
                    # Get the IP address
                    address = list_chunk.data.ip_key
                    # Get the hostname, if it was resolved by a DNS lookup
                    hostname = list_chunk.data.m_hostname[:list_chunk.data.
                                                          m_hostname_length]
                    # Check if client is validated
                    validated = bool(list_chunk.data.m_host_validated)
                    # Get the timestamp of the first connection of this host
                    first_seen = self.profile.UnixTimeStamp(
                        value=list_chunk.data.m_first_seen // 1000000)
                    # Get the timestamp of the last connection of this host
                    last_seen = self.profile.UnixTimeStamp(
                        value=list_chunk.data.m_last_seen // 1000000)
                    # Get the timestamp of the first error of this host
                    first_error_seen = self.profile.UnixTimeStamp(
                        value=list_chunk.data.m_first_error_seen // 1000000)
                    # Get the timestamp of the last error of this host
                    last_error_seen = self.profile.UnixTimeStamp(
                        value=list_chunk.data.m_last_error_seen // 1000000)

                    host_info += [
                        address, hostname, validated, first_seen, last_seen,
                        first_error_seen, last_error_seen
                    ]

                    error_counters = []
                    for counter in list_chunk.data.m_errors.m_counters:
                        error_counters.append(counter)

                    host_info = host_info + error_counters

                    result_dict.append(host_info)

            for value in result_dict:
                yield dict(task=task,
                           address=value[0],
                           hostname=value[1],
                           validated=value[2],
                           first_seen=value[3],
                           last_seen=value[4],
                           first_error_seen=value[5],
                           last_error_seen=value[6],
                           connect=value[7],
                           host_blocked=value[8],
                           nameinfo_transient=value[9],
                           nameinfo_permanent=value[10],
                           format=value[11],
                           addrinfo_transient=value[12],
                           addrinfo_permanent=value[13],
                           FCrDNS=value[14],
                           host_acl=value[15],
                           no_auth_plugin=value[16],
                           auth_plugin=value[17],
                           handshake=value[18],
                           proxy_user=value[19],
                           proxy_user_acl=value[20],
                           authentication=value[21],
                           ssl=value[22],
                           max_user_connection=value[23],
                           max_user_connection_per_hour=value[24],
                           default_database=value[25],
                           init_connect=value[26],
                           local=value[27])

""" 
mysqld-connections plugin implementation. 
It extracts informations about MySQL connections.
"""
class MySqldConnections(MySqld):
    name = "mysqld-connections"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="task", hidden=True),
        dict(name="thread_id", width=2),
        dict(name="host", width=14),
        dict(name="mysql_user", width=25),
        dict(name="connected", width=5),
        dict(name="connection_type", width=10),
        dict(name="last_event", width=20),
        dict(name="other_info", width=25)
    ]

    def __init__(self, **kwargs):
        super(MySqldConnections, self).__init__(**kwargs)
        self._mysqld_profile = None

    def collect(self):
        for task in self.filter_processes():
            if not self.init_for_task(task):
                continue

            if not self.init_collect():
                continue

            # Get thread arrays chunks
            thread_arrays = self.get_pfs_thread_array()

            result_dict = []

            for thread_array in thread_arrays:
                # Get information about users
                connection_dict = self.get_user_base_info(thread_array)

                for thr_id in connection_dict:
                    # Retrieve name of the connected user
                    username = connection_dict[thr_id][0]
                    # Retrieve client IP address of connection (or the hostname)
                    hostname = connection_dict[thr_id][1]
                    if hostname == '---':
                        continue
                    # Retrieve connection type
                    conn_type = connection_dict[thr_id][3]

                    # Retrieve connection attributes
                    # (only if connection is still active)
                    connect_attr = connection_dict[thr_id][4]

                    # Get the timestamp of the last event, generated in this
                    # connection
                    time_end = connection_dict[thr_id][5]

                    # Parse connect_attr string
                    if len(connect_attr) > 1:
                        other_info = binascii.hexlify(connect_attr)
                        in_string = False
                        is_var = True
                        is_val = False
                        strlen = 0
                        info = ''
                        curr_string = ''
                        for indx in range(0, len(other_info), 2):
                            ch = other_info[indx:indx + 2]

                            if in_string is False:
                                strlen = int(ch, 16)
                                in_string = True

                            else:
                                curr_string += str(binascii.unhexlify(ch),
                                                   'utf-8')
                                if len(curr_string) < strlen:
                                    continue
                                if is_var:
                                    curr_string += ': '
                                if is_val:
                                    curr_string += '\n'
                                info += curr_string
                                curr_string = ''
                                is_var = not is_var
                                is_val = not is_val
                                in_string = False

                        if not other_info.strip():
                            is_connected = False
                        else:
                            is_connected = True
                    else:
                        # If there aren't connection attributes,
                        # the connection is closed
                        info = ' '
                        is_connected = False
                    result_dict.append([
                        thr_id, hostname, username, is_connected, conn_type,
                        time_end, info
                    ])

            for value in result_dict:  # Order by stmt_id
                yield dict(
                    task=task,
                    thread_id=value[0],
                    host=value[1],
                    mysql_user=value[2],
                    connected=value[3],
                    connection_type=value[4],
                    last_event=value[5],
                    other_info=value[6],
                )

"""
mysqld-prep-stmts plugin implementation
Gathers prepared statements
"""
class MySqldPrepared(MySqld):
    name = "mysqld-prep-stmts"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="task", hidden=True),
        dict(name="stmt_id", width=2),
        dict(name="stmt_name", width=10),
        dict(name="stmt_sql_text", width=50),
        dict(name="mysql_user", width=15),
        dict(name="address", width=15),
        dict(name="owner_thread_id", width=2),
        dict(name="owner_event_id", width=2),
        dict(name="error_count", width=3),
        dict(name="rows_affected", width=3),
        dict(name="rows_sent", width=3),
        dict(name="rows_examined", width=3)
    ]

    def __init__(self, **kwargs):
        super(MySqldPrepared, self).__init__(**kwargs)
        self._mysqld_profile = None

    def collect(self):
        for task in self.filter_processes():
            if not self.init_for_task(task):
                continue

            if not self.init_collect():
                continue

            connection_dict = dict()
            results = []

            thread_arrays = self.get_pfs_thread_array()

            for thread_array in thread_arrays:
                # Get info about users
                connection_dict = self.get_user_base_info(thread_array)
            
            # Find prepared statements array
            prp_stmt_array = self.get_prep_stmts_array()

            # Scan the array
            for prp_stmt in prp_stmt_array:
                # Get the statement ID
                stmt_id = prp_stmt.m_stmt_id
                if stmt_id <= 0:
                    continue
                # Get the text of the prepared statement
                stmt_sql_text = prp_stmt.m_sqltext[:prp_stmt.m_sqltext_length]

                if stmt_sql_text.strip() is None or stmt_sql_text.isascii() is False:
                    continue
                # Get the name given to the prepared statement
                stmt_name = prp_stmt.m_stmt_name[:prp_stmt.m_stmt_name_length]
                # Get ID of thread in which the prepared statement has been defined
                owner_thread_id = prp_stmt.m_owner_thread_id
                # Get ID of the event that describes the prepared statement creation
                owner_event_id = prp_stmt.m_owner_event_id
                
                if owner_event_id not in connection_dict:
                    if self.plugin_args.force:
                        mysql_user = '---'
                        address = '---'
                    else:
                        continue
                else:
                    # Get the username of the user who have defined the statement
                    mysql_user = connection_dict[owner_thread_id][0]
                    # Get the IP address of that user
                    address = connection_dict[owner_thread_id][1]
                # Get statistics about the prepared statement
                error_count = prp_stmt.m_execute_stat.m_error_count
                rows_affected = prp_stmt.m_execute_stat.m_rows_affected
                rows_sent = prp_stmt.m_execute_stat.m_rows_sent
                rows_examined = prp_stmt.m_execute_stat.m_rows_examined

                results.append([
                    stmt_id, stmt_name, stmt_sql_text, mysql_user, address,
                    owner_thread_id, owner_event_id, error_count,
                    rows_affected, rows_sent, rows_examined
                ])

            for value in results:
                yield dict(task=task,
                           stmt_id=value[0],
                           stmt_name=value[1],
                           stmt_sql_text=value[2],
                           mysql_user=value[3],
                           address=value[4],
                           owner_thread_id=value[5],
                           owner_event_id=value[6],
                           error_count=value[7],
                           rows_affected=value[8],
                           rows_sent=value[9],
                           rows_examined=value[10])


class MysqldProfile(basic.ProfileLP64, basic.BasicClasses):
    __abstract = True

    # PFS_thread_array points to data field addresses + 0x40 (48 bytes)
    OFFSET = 48

    PRP_STMT_ARRAY_SIZE = 1024

    """ 
    This structures contains pointers to structures used by performance
    schema database
    """
    PFS_thread_array_vtype_64 = {
        "PFS_thread_array": [232, {
            "m_ptr": [72, ["Pointer", {
                "target": "PFS_thread"
            }]],
            "m_pointers":
            [96, ["Array", {
                "count": 16,
                "target": "Pointer"
            }]],
            "m_statements_history_array":
            [160, ["Pointer", {
                "target": "PFS_events_statements"
            }]],
            "m_session_connect_attrs_array":
            [184, ["Pointer", {
                "target": "String"
            }]],
        }]
    }

    """ 
    This structure contains information about last packet sent by a specific
    client
    """
    PFS_thread_vtype_64 = {
        "PFS_thread": [4224,{
            "m_event_id": [480, ["long unsigned int"]],
            "m_thread_internal_id": [568, ["long unsigned int"]],
            "m_username": [1740, ["String"]],
            "m_username_length": [1836, ["unsigned int"]],
            "m_hostname": [1840, ["String"]],
            "m_hostname_length": [2096, ["unsigned int"]],
            "m_dbname": [2100, ["String"]],
            "m_dbname_length": [2292, ["unsigned int"]],
            "m_groupname": [2296, ["String"]],
            "m_groupname_length": [2488, ["unsigned int"]],
            "m_connection_type": [2508, ["unsigned int"]],
            "m_start_time": [2512, ["long unsigned int"]],
            "m_processlist_info": [2528, ["String"]],  #1024
            "m_session_connect_attrs":
            [4200, ["Pointer", {
                "target": "String"
            }]]
        }]
    }

    """ 
    This structure contains a single element of the array that stores the 
    SQL statements received by clients
    """
    PFS_events_statements_vtype_64 = {
        "PFS_events_statements": [1456,{
            "m_thread_internal_id": [0, ["long unsigned int"]],
            "m_event_id": [8, ["long unsigned int"]],
            "m_end_event_id": [16, ["long unsigned int"]],
            "m_event_type": [24, ["unsigned int"]],
            "m_timer_start": [56, ["long unsigned int"]],  # picoseconds
            "m_timer_end": [64, ["long unsigned int"]],  # picoseconds
            "m_statement_id": [88, ["long unsigned int"]],
            "m_schema_name": [492, ["String"]],  # NAME_LEN = 192
            "m_schema_name_length": [684, ["unsigned int"]],
            "m_message_text": [696, ["String"]],
            "m_sql_errno": [1212, ["unsigned int"]],
            "m_sqlstate": [1216, ["String"]],
            "m_error_count": [1224, ["unsigned int"]],
            "m_warning_count": [1228, ["unsigned int"]],
            "m_rows_affected": [1232, ["long unsigned int"]],
            "m_rows_sent": [1240, ["long unsigned int"]],
            "m_rows_examined": [1248, ["long unsigned int"]],
            "m_sqltext": [1368, ["Pointer", {
                "target": "String"
            }]],
            "m_sqltext_length": [1376, ["unsigned int"]],
        }]
    }

    """ 
    This structures contains a list node. The list is double-linked and each
    node references a host_entry structure
    """
    List_vtype_64 = {
        "List": [24, {
            "prev": [0, ["Pointer", {
                "target": "List"
            }]],
            "next": [8, ["Pointer", {
                "target": "List"
            }]],
            "data": [16, ["Pointer", {
                "target": "host_entry"
            }]],
        }]
    }

    """ 
    This structure contains information about client hosts, which have connected
    to the server.
    """
    host_entry_vtype_64 = {
        "host_entry": [512,{
            "ip_key":
            [0, ["String"]],  # HOST_ENTRY_KEY_SIZE = INET6_ADDRSTRLEN = 46
            "m_hostname": [46, ["String"]],
            "m_hostname_length": [304, ["unsigned int"]],
            "m_host_validated": [308, ["unsigned int"]],
            "m_first_seen": [312, ["long unsigned int"]],
            "m_last_seen": [320, ["long unsigned int"]],
            "m_first_error_seen": [328, ["long unsigned int"]],
            "m_last_error_seen": [336, ["long unsigned int"]],
            "m_errors": [344, ["Host_errors"]]
        }]
    }

    """
    This structure contains statistics about host errors
    """
    Host_errors_vtype_64 = {
        "Host_errors": [168, {
            "m_counters":
            [0, ["Array", {
                "count": 21,
                "target": "long unsigned int"
            }]]
        }]
    }

    """
    This structure contains information about a prepared statement
    """
    PFS_prepared_stmt_vtype_64 = {
        "PFS_prepared_stmt": [1664, {
            "m_stmt_id": [24, ["long unsigned int"]],
            "m_stmt_name": [32, ["String"]],
            "m_stmt_name_length": [224, ["unsigned int"]],
            "m_sqltext": [228, ["String"]],
            "m_sqltext_length": [1252, ["unsigned int"]],
            "m_owner_thread_id": [1256, ["long unsigned int"]],
            "m_owner_event_id": [1264, ["long unsigned int"]],
            "m_owner_object_type": [1272, ["unsigned int"]],
            "m_prepare_stat": [1416, ["PFS_single_stat"]],
            "m_reprepare_stat": [1448, ["PFS_single_stat"]],
            "m_execute_stat": [1480, ["PFS_statement_stat"]]
        }]
    }

    """
    This structure contains statistics about a prepared statement
    """
    PFS_statement_stat_vtype_64 = {
        "PFS_statement_stat": [184, {
            "m_error_count": [32, ["long unsigned int"]],
            "m_rows_affected": [48, ["long unsigned int"]],
            "m_rows_sent": [64, ["long unsigned int"]],
            "m_rows_examined": [72, ["long unsigned int"]],
        }]
    }

    version_dict = {
        '8': [
            PFS_thread_array_vtype_64, PFS_thread_vtype_64,
            PFS_events_statements_vtype_64, List_vtype_64, host_entry_vtype_64,
            PFS_prepared_stmt_vtype_64, Host_errors_vtype_64,
            PFS_statement_stat_vtype_64
        ]
    }

    def __init__(self, version=None, **kwargs):
        super(MysqldProfile, self).__init__(**kwargs)

        profile = dict()

        for vtypes in self.version_dict['8']:
            profile.update(vtypes)

        self.add_types(profile)

    def get_connection_type(self, code):
        method_switcher = {
            0: "UNKNOWN",
            1: "TCP/IP",
            2: "UNIX DOMAIN",
            3: "NAMED PIPE (WINDOWS)",
            4: "SSL",
            5: "SHARED MEMORY (WINDOWS)",
            6: "LOCAL",  # Used by prepared statements
            7: "PLUGINS"
        }
        return method_switcher.get(code)

    def get_event_type(self, code):
        method_switcher = {
            0: "TRANSACTION",
            1: "STATEMENT",
            2: "STAGE",
            3: "WAIT"
        }
        return method_switcher.get(code)
