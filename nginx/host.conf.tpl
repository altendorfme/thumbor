upstream thumbor {
	server 127.0.0.1:8888 max_fails=3 fail_timeout=30s;
	keepalive 32;
}

server {
	listen 443 ssl;
	listen [::]:443 ssl;
    listen 443 quic reuseport;
    listen [::]:443 quic reuseport;
	http2 on;
	include global/http3.conf;
	
	# Server name to listen for
	server_name {{DOMAIN}};

	# Path to document root
	root _;

	# Paths to certificate files.
    ssl_certificate /etc/letsencrypt/live/{{DOMAIN}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{DOMAIN}}/privkey.pem;

	# File to be used as index
	index index.html;

	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
	ssl_dhparam /etc/ssl/certs/dhparam.pem;
	ssl_prefer_server_ciphers off;
	ssl_session_tickets off;
	ssl_session_cache shared:SSL:10m;
	ssl_session_timeout 1h;

	# Use HTTPS exclusively for 1 year, uncomment one. Second line applies to subdomains.
	add_header Strict-Transport-Security "max-age=31536000;";
	# add_header Strict-Transport-Security "max-age=31536000; includeSubdomains;";

	location ~* /\.(?!well-known\/) {
		access_log off;
		error_log off;
		deny all;
	}

	location ~\.(ini|log|conf)$ {
		access_log off;
		error_log off;
		deny all;
	}

	location ~* /(?:uploads|files)/.*\.php$ {
		access_log off;
		error_log off;
		deny all;
	}

	location ^~ /favicon.ico {
		access_log off;
		error_log off;
		deny all;
	}

	# Hide Nginx version in error messages and reponse headers.
	server_tokens off;

	# Don't allow pages to be rendered in an iframe on external domains.
	add_header X-Frame-Options "SAMEORIGIN" always;

	# MIME sniffing prevention
	add_header X-Content-Type-Options "nosniff" always;

	# Enable cross-site scripting filter in supported browsers.
	add_header X-Xss-Protection "1; mode=block" always;

	# Increase client body size for image uploads
	client_max_body_size 50M;
	
	location / {
		proxy_pass http://thumbor;
		proxy_http_version 1.1;
		proxy_set_header Connection "";
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Proto $scheme;
		proxy_set_header X-Forwarded-Host $host;
		proxy_set_header X-Forwarded-Server $host;
		
		# Preserve original request URI for Thumbor
		proxy_set_header X-Original-URI $request_uri;
		
		# Pass through Accept header for format negotiation (WebP, AVIF support)
		proxy_set_header Accept $http_accept;
		
		# Pass through User-Agent for better format detection
		proxy_set_header User-Agent $http_user_agent;
		
		# Timeout configurations optimized for image processing
		proxy_connect_timeout 60s;
		proxy_send_timeout 120s;
		proxy_read_timeout 120s;
		
		# Buffer configuration for large images
		proxy_buffering on;
		proxy_buffer_size 128k;
		proxy_buffers 4 256k;
		proxy_busy_buffers_size 256k;
		proxy_temp_file_write_size 256k;
		proxy_max_temp_file_size 1024m;
		
		# Ignore client abort for long-running image processing
		proxy_ignore_client_abort on;
		
		# Don't log successful image requests to reduce noise
		access_log off;
		
		# CORS headers for cross-origin image requests
		add_header Access-Control-Allow-Origin "*" always;
		add_header Access-Control-Allow-Methods "GET, HEAD, OPTIONS" always;
		add_header Access-Control-Allow-Headers "Origin, X-Requested-With, Content-Type, Accept, Authorization, Cache-Control" always;
		add_header Access-Control-Max-Age 3600 always;
		
		# Handle preflight requests
		if ($request_method = 'OPTIONS') {
			return 204;
		}
	}
}

server {
    listen 80;
    listen [::]:80;
    server_name {{DOMAIN}};
    
    # Let's Encrypt ACME challenge
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
        try_files $uri =404;
    }
    
    # Redirect all other HTTP traffic to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}