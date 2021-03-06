The piuparts-server package installs a piuparts server along the lines of
http://piuparts.debian.org/.

Before running the server, edit /etc/piuparts.conf appropriately (install
piuparts-slave (which ships that file), too, or use the template
/usr/share/doc/piuparts-master/piuparts.conf.sample), to define
'sections' to be tested (e.g. 'sid') and define references to the Debian
mirror. Note that the server can place a significant load on the
repository. Consider setting up a local mirror, or a caching proxy for http
and apt-get, to reduce the load. Running multiple slaves on a fast host can
easily saturate a 100 MBit link.

Edit /etc/sudoers.d/piuparts to grant permissions to the piupartss user.
Start the server using /usr/sbin/piuparts_slave_run, which will launch a
'screen' session. The slave will launch a master process via ssh, as needed,
to retrieve work and return results. Use /usr/sbin/piuparts_slave_join to
join the screen session.

Logs are stored under /var/lib/piuparts. They are stored there because they
are basically the result of piuparts running.

There are maintenance cron jobs defined in /etc/cron.d/piuparts-*.cron. In
particular, piuparts-report will create a web summary, defaulting to
http://localhost/piuparts, served by Apache. Uncomment the lines in the cron
file to enable the jobs.

