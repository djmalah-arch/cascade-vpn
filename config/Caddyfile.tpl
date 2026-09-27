{
	http_port 80
	https_port 8443
	servers 127.0.0.1:8443 {
		listener_wrappers {
			proxy_protocol {
				timeout 5s
				allow 127.0.0.1/32
			}
			tls
		}
		protocols h1 h2
	}
}
http://{{DOMAIN}} {
	redir https://{{DOMAIN}}{uri} permanent
}
{{DOMAIN}}:8443 {
	bind 127.0.0.1
	encode
	@sub path /api/sub/*
	handle @sub {
		reverse_proxy 127.0.0.1:3000
	}
	handle /sub/* {
		reverse_proxy 127.0.0.1:8090
	}
	handle /c/* {
		reverse_proxy 127.0.0.1:8090
	}
	handle_path /app/* {
		root * /srv/app
		@hidden path /apps.json /.*
		respond @hidden 404
		header Content-Disposition attachment
		file_server
	}
	@login query k={{COOKIE}}
	handle @login {
		header Set-Cookie "gv={{COOKIE}}; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Strict"
		redir /admin 302
	}
	@auth header_regexp Cookie gv={{COOKIE}}
	handle @auth {
		handle /admin* {
			reverse_proxy 127.0.0.1:8090
		}
		handle /login* {
			reverse_proxy 127.0.0.1:8090
		}
		handle /logout {
			reverse_proxy 127.0.0.1:8090
		}
		handle {
			forward_auth 127.0.0.1:8090 {
				uri /auth/check
			}
			reverse_proxy 127.0.0.1:3000
		}
	}
	handle {
		abort
	}
}
