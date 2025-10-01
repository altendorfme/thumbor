# Thumbor Docker

Docker image for [Thumbor](https://thumbor.readthedocs.io/) an open-source smart imaging service that enables on-demand crop, resizing and filtering of images.

## ✨ Features

- 🚀 **Production Ready**: Built with security and performance in mind
- 🔒 **SSL/TLS Support**: Automatic Let's Encrypt certificate management
- 🌐 **HTTP/3 & QUIC**: Latest web protocols for improved performance
- 🔄 **Auto Format Detection**: WebP, AVIF, and HEIF support with automatic format selection
- 📦 **Multiple Storage Options**: File system, AWS S3, and more
- 🎯 **Smart Detection**: Face and feature detection for intelligent cropping
- 🛡️ **Security Headers**: Comprehensive security headers and CORS support
- 📊 **Process Management**: Supervisord for reliable service management
- 🔧 **Configurable**: Extensive configuration options via environment variables
- 📱 **Mobile Optimized**: Responsive image delivery for all devices

## 🚀 Quick Start

### Using Docker

Check [`docker-compose.yml`](./docker-compose.yml)

## ⚙️ Configuration

### Environment Variables

#### SSL Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `DOMAIN` | `localhost` | Domain name for SSL certificate |

#### Thumbor Core Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `THUMBOR_LOG_LEVEL` | `info` | Log level (debug, info, warning, error) |
| `THUMBOR_NUM_PROCESSES` | `4` | Number of Thumbor processes |
| `SECURITY_KEY` | `MY_SECURE_KEY` | Secret key for URL signing |
| `ALLOW_UNSAFE_URL` | `false` | Allow unsigned URLs (development only) |

#### Image Processing
| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_WIDTH` | `2000` | Maximum image width in pixels |
| `MAX_HEIGHT` | `2000` | Maximum image height in pixels |
| `QUALITY` | `85` | JPEG quality (1-100) |
| `AUTO_WEBP` | `true` | Enable automatic WebP conversion |
| `AUTO_AVIF` | `true` | Enable automatic AVIF conversion |
| `PROGRESSIVE_JPEG` | `true` | Enable progressive JPEG |

#### Storage Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE` | `thumbor.storages.file_storage` | Storage backend |
| `RESULT_STORAGE` | `thumbor.result_storages.file_storage` | Result storage backend |
| `STORAGE_EXPIRATION_SECONDS` | `2592000` | Storage expiration (30 days) |

#### Performance Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `ENGINE_THREADPOOL_SIZE` | `4` | Thread pool size for image processing |
| `GC_INTERVAL` | `30` | Garbage collection interval in seconds |

### Complete Environment Variables List

For a full list of available environment variables, see the [`thumbor.conf.tpl`](./thumbor.conf.tpl) file.

## 🔧 Usage Examples

### Basic Image Resize

```bash
# Resize to 300x200
https://site.xyz/300x200/https://example.com/image.jpg

# Resize with smart crop
https://site.xyz/300x200/smart/https://example.com/image.jpg
```

### Advanced Filters

```bash
# Apply brightness and contrast
https://site.xyz/filters:brightness(20):contrast(10)/https://example.com/image.jpg

# Convert to grayscale and add blur
https://site.xyz/filters:grayscale():blur(2)/https://example.com/image.jpg
```

### Format-Specific URLs

```bash
# Force WebP format
https://site.xyz/filters:format(webp)/https://example.com/image.jpg

# Force AVIF format (if supported)
https://site.xyz/filters:format(avif)/https://example.com/image.jpg
```

## 📁 Data Persistence

The following directories should be persisted for production use:

- `/data` - Image storage and cache
- `/etc/letsencrypt` - SSL certificates
- `/var/log/supervisor` - Application logs
- `/var/log/nginx` - Nginx logs

## 🔍 Health Checks

The container includes health checks accessible at:
- `http://localhost:8888/healthcheck` - Thumbor health check
- `http://localhost/healthcheck` - Nginx proxy health check

## 📊 Monitoring

### Logs

```bash
# View all logs
docker-compose logs -f

# View Thumbor logs only
docker-compose logs -f thumbor

# View specific log files
docker exec -it thumbor-server tail -f /var/log/supervisor/thumbor.log
```

### Performance Issues

1. **Increase process count:**
```bash
export THUMBOR_NUM_PROCESSES=8
```

2. **Enable SIMD optimization:**
```bash
docker build --build-arg SIMD_LEVEL=avx2 -t thumbor:optimized .
```

3. **Tune caching:**
```bash
export STORAGE_EXPIRATION_SECONDS=86400  # 1 day
export RESULT_STORAGE_EXPIRATION_SECONDS=86400
```

## 📚 Documentation

- [Thumbor Documentation](https://thumbor.readthedocs.io/)
- [Thumbor URL Format](https://thumbor.readthedocs.io/en/latest/usage.html)
- [Available Filters](https://thumbor.readthedocs.io/en/latest/filters.html)
- [Configuration Options](https://thumbor.readthedocs.io/en/latest/configuration.html)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [thumbor/thumbor](https://github.com/thumbor/thumbor) - Original Thumbor project
- [MinimalCompact/thumbor](https://github.com/MinimalCompact/thumbor) - Alternative Docker implementation
- [APSL/thumbor](https://github.com/APSL/thumbor) - Another Docker variation