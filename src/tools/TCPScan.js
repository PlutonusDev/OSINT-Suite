const fs = require("fs");
const net = require("net");
const iac = require("./iac");

class TCPScan {
	constructor(opts) {
		this.opts = opts;
		this.opts.bannerlen = 512;
		this.opts.timeout = 2000;
		
		this.cb = null;
		
		this.result = {
			ip:opts.ip,
			port:opts.port,
			bannerraw:[],
			banner:"",
			status:null,
			open:false
		}
		
		this.socket = null;
		this.bufArray = [];
	}
	
	formatBanner(str) {
		str = new(require("string_decoder").StringDecoder)("utf-8").write(str);
		str = str.toString();
		str = str.replace(/\n/gm,"\\n");
		str = str.replace(/\r/gm,"\\r");
		str = str.replace(/\t/gm,"\\t");
		str = str.replace(/ *$/,"");
		str = str.replace(/^ */,"");
		str = str.substr(0,this.opts.bannerlen);
		return str;
	}
	
	analyzePort(c) {
		return new Promise((res, rej) => {
			this.cb=c;
			this.res=res;
			
			this.socket = net.createConnection(this.opts.port, this.opts.ip);
			this.socket.removeAllListeners("timeout");
			this.socket.setTimeout(this.opts.timeout);
			
			this.socket.on("close",this._close.bind(this));
			this.socket.on("error",this._error.bind(this));
			this.socket.on("connect",this._connect.bind(this));
			this.socket.on("timeout",this._timeout.bind(this));
			this.socket.on("data",this._data.bind(this));
		});
	}
	
	_send(t) {
		if(this.bufArray.length) this.result.raw = Buffer.concat(this.bufArray);
		if(this.result.banner) this.result.banner = this.formatBanner(this.result.banner);
		
		if(!this.result.status) {
			if(!this.result.open) {
				if(t)this.result.status = "FAIL [Timeout]";
				if(!t)this.result.status = "FAIL [CLOSED]";
			} else {
				this.result.status = "OPEN";
			}
		}
		
		if(this.socket) {
			this.socket.destroy();
			delete this.socket;
		}
		this.res();
	}
	_close() {
		if(!this.result.banner)this.result.open = false;
		this._send();
	}
	_error(e) {
		if(e.message.match(/ECONNREFUSED/)) {
			return this.result.status = "FAIL [Refused]";
		}
		if(e.message.match(/EHOSTUNREACH/)) {
			return this.result.status = "FAIL [Unreachable]";
		}
		this.result.status = `FAIL [${e.message}]`;
	}
	_connect() {
		this.result.open = true;
	}
	_timeout() {
		if(!this.result.open)this.result.status = "FAIL [Timeout]";
		if(this.result.open)this.result.status = "OPEN";
		if(this.socket)this.socket.destroy();
	}
	_data(buf) {
		this.bufArray.push(buf);
		buf = iac.negotiate(buf, this.socket);
		if(this.result.banner.length < this.opts.bannerlen) {
			let d = buf.toString("ascii");
			return this.result.banner += d;
		}
		this.socket && this.socket.destroy();
	}
}

module.exports = TCPScan;