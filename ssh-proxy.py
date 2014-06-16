#!/usr/bin/python3.3

import binascii
import logging
import logging.handlers
import select
import socket
import threading

import paramiko

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.handlers.TimedRotatingFileHandler('ssh-proxy.log', when='W0', utc=True, delay=True))

class stderrFilter(logging.Filter):
	def filter(self, record):
		minlvl = logging.INFO
		if record.name[:9] == 'paramiko.':
			minlvl = logging.WARNING
		return record.levelno >= minlvl
stderr_handler = logging.StreamHandler()
stderr_handler.addFilter(stderrFilter())
logger.addHandler(stderr_handler)

host_key = paramiko.RSAKey(filename='ssh-proxy-host-rsa.key')

remhosts = {}
ep = select.epoll()

def a2b_hexcolon(data):
	if len(data) % 3 != 2:
		raise binascii.Error
	for c in data[2::3]:
		if c != ':':
			raise binascii.Error
	x = ''
	for i in range(0, len(data), 3):
		x += data[i:i+2]
	return binascii.a2b_hex(x)

def b2a_hexcolon(data):
	x = binascii.b2a_hex(data).decode('ascii')
	rv = ''
	for i in range(0, len(x), 2):
		rv += ':' + x[i:i+2]
	return rv[1:]

userparse = (a2b_hexcolon, binascii.a2b_hex, binascii.a2b_base64)

class relay_feed_hack:
	def __init__(self, channel):
		self.channel = channel
		self._sending = b''
		self._feedlock = threading.Lock()
	
	def _close(self):
		self.channel.close()
		self.channel.otherend.close()
	
	def close(self):
		logger.info('%s: Closed by %s' % (self.channel.linkinfo, self.channel.remaddr))
		threading.Thread(target=self._close).start()
	
	def _feed(self):
		while True:
			try:
				sent = self.channel.otherend.send(self._sending)
			except:
				logger.error('%s: Error sending to %s' % (self.channel.linkinfo, self.channel.otherend.remaddr))
				threading.Thread(target=self._close).start()
			with self._feedlock:
				self._sending = self._sending[sent:]
				if len(self._sending) == 0:
					break
	
	def feed(self, data):
		with self._feedlock:
			already_have_data = len(self._sending)
			self._sending += data
		if not already_have_data:
			threading.Thread(target=self._feed).start()

def sendList(channel):
	for (rhkfp, rh) in remhosts.items():
		channel.send("%s\t%s\n" % (b2a_hexcolon(rhkfp), rh.username))
	channel.close()

def _pair_link(ac, bc, linkinfo, a):
	ac.linkinfo = linkinfo
	ac.otherend = bc
	ac.in_buffer = relay_feed_hack(ac)
	ac.remaddr = a.remaddr

def pair_link(srcchannel, dstchannel, linkinfo, src, dst):
	_pair_link(srcchannel, dstchannel, linkinfo, src)
	_pair_link(dstchannel, srcchannel, linkinfo, dst)

class Server(paramiko.ServerInterface):
	def get_allowed_auths(self, username):
		if username == 'client':
			return 'none'
		return 'publickey'
	
	def check_auth_none(self, username):
		self.username = username
		if username == 'client':
			return paramiko.AUTH_SUCCESSFUL
		return paramiko.AUTH_FAILED
	
	def check_auth_publickey(self, username, key):
		self.username = username
		self.ssh_key = key
		return paramiko.AUTH_SUCCESSFUL
	
	def check_port_forward_request(self, address, port):
		if self.username == 'client':
			return None
		self.fwd_dest = (address, port)
		keyfp = self.ssh_key.get_fingerprint()
		remhosts[keyfp] = self
		self.hostinfo = '%s (%s)' % (b2a_hexcolon(keyfp), repr(self.username))
		logger.info("Registered %s to %s %s" % (self.hostinfo, self.remaddr, self.fwd_dest))
		return port
	
	def check_channel_request(self, kind, chanid):
		if kind == 'session':
			return paramiko.OPEN_SUCCEEDED
		return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
	
	def check_channel_exec_request(self, channel, command):
		if command == 'ls':
			threading.Thread(target=sendList, args=(channel,)).start()
			return True
		q = None
		for tryup in userparse:
			try:
				q = tryup(command)
				if len(q) == 16:
					break
				else:
					q = None
			except binascii.Error:
				continue
		if q is None:
			return False
		if q not in remhosts:
			return False
		dst = remhosts[q]
		fwd_src = self.remaddr[:2]
		try:
			dstchannel = dst.t.open_forwarded_tcpip_channel(fwd_src, dst.fwd_dest)
		except paramiko.SSHException:
			return False
		linkinfo = '0x%x' % (id(channel),)
		pair_link(channel, dstchannel, linkinfo, self, dst)
		logger.info("%s: Connected %s to %s" % (channel.linkinfo, fwd_src, dst.hostinfo))
		return True

sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', 2200))
sock.listen(100)

while True:
	try:
		client, remaddr = sock.accept()
		t = paramiko.Transport(client)
		t.load_server_moduli()
		t.add_server_key(host_key)
		server = Server()
		server.t = t
		server.remaddr = remaddr
		t.start_server(server=server)
	except Exception as e:
		logger.error('error: %s' % (e,))
