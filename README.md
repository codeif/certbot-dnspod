# certbot-dnspod

A certbot plugin for DNSPod

## 安装

```
pip install certbot-dnspod
```

## 创建证书

```
sudo certbot certonly \
--authenticator certbot-dnspod \
--certbot-dnspod-credentials ~/.secrets/certbot/dnspod.ini \
-d example.com \
-d *.example.com
```

其中~/.secrets/certbot/dnspod.ini为配置文件路径，内容

```
certbot_dnspod_token_id = <your token id>
certbot_dnspod_token = <your token>
```

chmod

```
chmod 600 ~/.secrets/certbot/dnspod.ini
```

## 参数

官方插件是参数形式是
```
--dns-cloudflare-credentials
```

而第三方插件的参数是::

```
--authenticator certbot-dnspod
```

或者

```
-a certbot-dnspod
```

## 其他

- [certbot命令行参数](https://eff-certbot.readthedocs.io/en/stable/using.html#certbot-command-line-options)
- [编写一个certbot插件](https://certbot.eff.org/docs/contributing.html#writing-your-own-plugin)
- [官方插件](https://certbot.eff.org/docs/using.html#dns-plugins)
- [三方插件](https://certbot.eff.org/docs/using.html#third-party-plugins)
- [poetry加自定义的entry_points](https://python-poetry.org/docs/pyproject/#plugins)

