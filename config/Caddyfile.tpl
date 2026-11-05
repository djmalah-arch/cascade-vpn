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
	@routeCheck path /route-check
	handle @routeCheck {
		header Cache-Control no-store
		respond "{http.request.remote.host}" 200
	}
	@sub path /api/sub/*
	handle @sub {
		reverse_proxy 127.0.0.1:3000
	}
	handle /sub/* {
		reverse_proxy unix//run/geovpn-public/http.sock
	}
	handle /c/* {
		reverse_proxy unix//run/geovpn-public/http.sock
	}
	handle /app/* {
		reverse_proxy unix//run/geovpn-public/http.sock
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
		root * /srv/public
		try_files {path} /index.html
		file_server
	}
}
