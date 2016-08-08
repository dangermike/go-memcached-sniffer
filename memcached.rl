// GO CODE GENERATED BY RAGEL. DO NOT EDIT BY HAND.
package main

import (
	log "github.com/Sirupsen/logrus"
)

// Memcache protocol documentation at https://github.com/memcached/memcached/blob/master/doc/protocol.txt
// add <key> <flags> <exptime> <bytes> [noreply]\r\n<body>/r/n
// append <key> <flags> <exptime> <bytes> [noreply]\r\n<body>/r/n
// cache_memlimit <numeric>\r\n
// cas <key> <flags> <exptime> <bytes> <cas unique> [noreply]\r\n
// delete <key>\r\n
// flush_all\r\n
// flush_all <numeric>\r\n
// get <key>\r\n
// gets <key>*\r\n
// incr|decr <key> <value> [noreply]\r\n
// lru_crawler <enable|disable>\r\n
// prepend <key> <flags> <exptime> <bytes> [noreply]\r\n<body>/r/n
// quit\r\n
// replace <key> <flags> <exptime> <bytes> [noreply]\r\n<body>/r/n
// set <key> <flags> <exptime> <bytes> [noreply]\r\n<body>/r/n
// slabs automove <0|1>\r\n
// slabs reassign <source class> <dest class>\r\n
// stats <args>\r\n
// stats\r\n
// touch <key> <exptime> [noreply]\r\n
// verbosity\r\n
// version\r\n
// watch <fetchers|mutations|evictions>\r\n

%%{
	machine memcached;
	write data;

			action ClearState {
				expiry = int(0)
				expectedLen, foundLen = 0, 0
				keyString = ""
			}
			action NeedMoreBody { expectedLen > foundLen }
			action AddExpectedLen { expectedLen = expectedLen * 10 + (int(fc) - int('0')) }
			action AddFoundLenLen { foundLen = foundLen + 1 }
			action AddExpiryTime { expiry = expiry * 10 + (int(fc) - '0') }
			action AddKeyString {
				keyString = keyString + string(fc)
			} # this could be made faster

			crlf = '\r\n';
			mk_key = ((0x21..0x7f|0x80..0xff) @ AddKeyString)+;
			flags = digit+;
			exptime = (digit @AddExpiryTime)+;
			body_len = (digit @AddExpectedLen)+;
			body = ( any when NeedMoreBody >AddFoundLenLen )+;

			cas_key = [0-9]+;
			atomic_val = [0-9]+;
			noreply = ' noreply'?;

			cmd_del = ('delete');
			cmd_gets = ('get'|'gets');
			cmd_cas = 'cas';
			cmd_atomic = ('incr'|'decr');
			cmd_write = ('set'|'add'|'replace'|'append'|'prepend');
			cmd_touch = 'touch';

			do_atomic = cmd_atomic ' ' mk_key ' ' atomic_val noreply;
			do_cas = cmd_cas	' ' mk_key	' ' flags ' '	exptime	' ' body_len	' ' cas_key noreply crlf body;
			do_flush_all = 'flush_all' (' ' digit+)?;
			do_get_del = cmd_del ' ' mk_key;
			do_gets = cmd_gets	' ' mk_key+;
			do_lru_crawler = 'lru_crawler ' ('enable'|'disable');
			do_memlimit = 'cache_memlimit ' digit+;
			do_ones = ('version'|'verbosity'|'quit');
			do_slabs = 'slabs automove ' [01];
			do_slabs_reassign = 'slabs reassign ' '-'? digit+ ' ' digit+;
			do_stats = 'stats'( ' ' any+)?;
			do_touch = cmd_touch ' ' mk_key ' ' exptime noreply;
			do_watch = 'watch ' ('fetchers'|'mutations'|'evictions');
			do_write = cmd_write ' ' mk_key ' ' flags ' ' exptime ' ' body_len noreply crlf body;

			main := ((do_atomic
							|do_cas
							|do_flush_all
							|do_get_del
							|do_gets
							|do_lru_crawler
							|do_memlimit
							|do_ones
							|do_slabs
							|do_slabs_reassign
							|do_stats
							|do_touch
							|do_watch
							|do_write
							) crlf @ClearState)+;


			#' ' mk_key ' ' digit+ ' ' digit+ noreply '\r\n'?;
}%%

// ParseResult holds the results of a memcached protocol parse
type ParseResult struct {
	// BufferLength is the size of the buffer passed into the parser
	BufferLength   int
  // ParserState is the state of the Ragel parser
	ParserState    int
	// ParserOffset is the offset into the provided buffer where the parser last succeeded
	ParserOffset   int
	// ExpectedLength is the expected body length for set operations and similar
	ExpectedLength int
	// FoundLength is the number of bytes read a of the ParserOffset for set operations and similar
	FoundLength    int
	// KeyString is the key for the most recently read command
	KeyString      string
}

func (pr ParseResult) ToLogFields() log.Fields {
	return log.Fields {
		"BufferLength":   pr.BufferLength,
		"ParserState":    pr.ParserState,
		"ParserOffset":   pr.ParserOffset,
		"ExpectedLength": pr.ExpectedLength,
		"FoundLength":    pr.FoundLength,
		"KeyString":      pr.KeyString,
	}
}

func parseSession(data []byte) ParseResult {
	var (
		cs, p, pe = 0, 0, len(data)
		// eof = len(data)
		expiry = int(0)
		expectedLen, foundLen = 0, 0
		keyString = ""
		// mark = 0
	)
	%%{

		write init;
		write exec;
	}%%

	pr := ParseResult{
		BufferLength:   len(data),
		ParserState:    cs,
		ParserOffset:   p,
		ExpectedLength: expectedLen,
		FoundLength:    foundLen,
		KeyString:      keyString,
	}
	return pr
}
