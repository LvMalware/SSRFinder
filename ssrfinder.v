module main

import io
import os
import flag
import net.http
import net.urllib
import crypto.md5

fn ssrf_fuzz(server string, queue chan string) int {
	for {
		line := <-queue or { break }
		mut url := urllib.parse(line) or { continue }
		mut query := url.query()
		mut target := urllib.parse(server) or { break }
		target.host = md5.hexhash(url.hostname() + url.escaped_path()) + "." + target.hostname()
		for key, val in query.to_map() {
			query.set(key, target.str())
			url.raw_query = query.encode()
			http.get(url.str()) or { }
			query.set(key, val[0])
		}
	}
	return 0
}

fn main() {
	mut parser := flag.new_flag_parser(os.args)
	parser.application("SSRFinder")
	parser.version("0.0.1")
	parser.skip_executable()
	input := parser.string('input', `i`, '-', "Input file with URLs (reads from stdin by default)")
	server := parser.string('server', `s`, '', "Burp collaborator/Interactsh host")
	threads := parser.int('threads', `t`, 10, "Number of concurrent threads")
	parser.finalize() or {
		println("[!] Error while parsing args. Exiting")
		return
	}

	if server.len < 1 {
		println("[!] You must provide an OOB server (option -s)")
		return
	}

	if threads < 1 {
		println("[!] Invalid number of threads: $threads")
		return
	}

	mut file := os.stdin()
	if input != '-' {
		file = os.open(input) or {
			println("[!] Failed to open $input")
			return
		}
	}

	mut list := []thread int{}
	mut queue := chan string{}
	for _ in 0 .. threads {
		list << go ssrf_fuzz(server, queue)
	}

	mut reader := io.new_buffered_reader(io.BufferedReaderConfig{file, 128 * 1024, 2})

	for reader.end_of_stream() == false {
		line := reader.read_line() or { continue }
		queue <-line
	}
	file.close()
	reader.free()
	queue.close()

	for thread in list {
		thread.wait()
	}
}
