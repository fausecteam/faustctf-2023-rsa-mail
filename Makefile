SERVICE := rsa-mail
DESTDIR ?= dist_root
SERVICEDIR ?= /srv/$(SERVICE)

.PHONY: build install

build:
	echo nothing to build

install: build
	mkdir -p $(DESTDIR)$(SERVICEDIR)
	cp -r docker-compose.yml $(DESTDIR)$(SERVICEDIR)
	mkdir -p $(DESTDIR)$(SERVICEDIR)/rsa-mail
	cp -r rsa-mail/Dockerfile* rsa-mail/static rsa-mail/requirements.txt rsa-mail/app.py $(DESTDIR)$(SERVICEDIR)/rsa-mail/
	mkdir -p $(DESTDIR)/etc/systemd/system/faustctf.target.wants/
	ln -s /etc/systemd/system/docker-compose@.service $(DESTDIR)/etc/systemd/system/faustctf.target.wants/docker-compose@rsa-mail.service

