const { get } = require("snekfetch");
const chalk = require("chalk");
const jssoup = require("jssoup").default;
const ports = require("../../data/domain").ports;
const TCPScan = require("../../tools/TCPScan");

module.exports = {
	whoisLookup: domain => {
		return new Promise(async (res, rej) => {
			get(`https://who.is/whois/${domain}`).then(resp => {
				let soup = new jssoup(resp.body);
				if(soup.find("pre")) {
					res(soup.find("pre").nextElement._text)
				} else {
					res("\nError: Cannot gather whois info.");
				}
			});
		});
	},
	
	portScan: (ip, vorp, ok) => {
		return new Promise(async (res, rej) => {
			promises = [];
			ports.forEach(async port => {
				promises.push(new Promise((res, rej) => {
					let scanner = new TCPScan({
						ip: ip,
						port: port.number
					});
					scanner.analyzePort().then(()=>{
						ok(vorp,`${port.name} [${port.number}]\t${scanner.result.status}`);
						res();
					}).catch(e=>console.log(e));
				}));
			});
			Promise.all(promises).then(() => res());
		});
	},
	
	potentialTargetScan: (domain, vorp, ok) => {
		return new Promise(async (res, rej) => {
			let targets = [];
			await get("https://raw.githubusercontent.com/danielmiessler/RobotsDisallowed/master/curated.txt").then(resp => {
				resp.body.toString().replace("*","");
				targets = resp.body.toString().split("\n");
			});
			promises = [];
			targets.forEach(async target => {
				promises.push(new Promise((res, rej) => {
					if(!target)return;
					get(`http://${domain}/${target}`).then(resp => {
						ok(vorp,`${chalk.green("TARGET")} ${target}`);
						res();
					}).catch(() => {
						//ok(vorp,`${chalk.red("FAILED")} ${target}`);
						res();
					});
				}));
			});
			Promise.all(promises).then(() => res()).catch(()=>res());
		});
	}
}