const vorp = require("vorpal")();
const chalk = vorp.chalk
const clear = require("clear");
const dns = require("dns");
const inquirer = require("inquirer");
const phone = require("phone");
const scanners = {
	phone: require("./lib/phone/scanner"),
	//social: require("./lib/social/scanner"),
	domain: require("./lib/domain/scanner")
}

log = (self, msg) => {self.log(`    [~] ${msg}`);}
ok = (self, msg) => {self.log(`    ${chalk.green("[+]")} ${msg}`);}
err = (self, msg) => {self.log(`    ${chalk.red("[!]")} ${msg}`);}

vorp
	.command("recon <type>", "Begin reconnaissance.")
	.autocomplete(["phone", "social", "domain"])
	.option("-d, --deep", "Deep reconnaissance.")
	.option("-v, --verbose", "Show debug messages.")
	.action((a,c) => {
		switch(a.type) {
			case "phone":
				inquirer.prompt([{
					name: "phone",
					type: "input",
					message: `Enter a phone number to ${a.options.deep ? "deep " : ""}recon:`,
					validate: val => {
						return phone(val)[0] ? true : `Please enter a valid domestic or international phone number.\\n   International numbers require a prefixing ${chalk.yellow("+")}`
					}
				}]).then(async resp => {
					log(vorp,"Contacting numverify...");
					await scanners.phone.localityScan(phone(resp.phone)[0].substr(1)).then(info => {
						if(a.options.verbose) log(vorp,chalk.magenta("[V]") + " Gathered secret: " + chalk.green(info.key));
						if(a.options.verbose) log(vorp,chalk.magenta("[v]") + " Generated token: " + chalk.green(info.secret));
						if(info.data.valid) {
							ok(vorp,"Local Format: " + chalk.green(info.data.local_format || "Unknown"));
							ok(vorp,"Intl. Format: " + chalk.green(info.data.intl_format || "Unknown"));
							ok(vorp,"Country:      " + chalk.green(info.data.country_name || "Unknown") + " (" + chalk.green(info.data.country_code || "N/A") + ")");
							ok(vorp,"Carrier:      " + chalk.green(info.data.carrier || "Unknown"));
							ok(vorp,"Line Type:    " + (info.data.line_type=="mobile" ? (chalk.green("Mobile") + chalk.yellow("  ! Possibly a VOIP number.")) : (chalk.green("Landline") + chalk.yellow("  ! Possibly a fixed VOIP number."))));
						} else err(vorp,"Invalid number entered, please include area code.");
					});
					vorp.log();
					c();
				});
				break;
			case "social":
				inquirer.prompt([{
					name: "user",
					type: "input",
					message: `Enter a username to ${a.options.deep ? "deep " : ""}recon:`,
					validate: val => {
						return val.length>3 ? true : false
					}
				}]).then(async resp => {
					c();
				});
				break;
			case "domain":
				inquirer.prompt([{
					name: "domain",
					type: "input",
					message: `Enter a domain name to ${a.options.deep ? "deep " : ""}recon:`,
					validate: val => {
						return /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/.test(val) ? true : `Please enter a valid domain name, do not include ${chalk.yellow("http://www")} or trailing ${chalk.yellow("/")}.`
					}
				}]).then(async resp => {
					let ip;
					dns.lookup(resp.domain, (e,a,f) => {
						ok(vorp,`DNS Response: [IPv${f}] ${a}`);
						ip = a;
					});
					vorp.log();
					log(vorp,`Contacting who.is...`);
					await scanners.domain.whoisLookup(ip).then(async res => {
						let whois = res.split("\n");
						whois.shift();
						whois.pop();
						for(entry of whois) {
							if(!entry) return;
							ok(vorp,`${entry.split(":")[0] + " ".repeat(38-entry.split(":")[0].length)} ${chalk.green(entry.split(":")[1]||"")}`);
						}
						vorp.log();
						log(vorp,"Starting network scan...");
						log(vorp,"Running TCP portscan...");
						await scanners.domain.portScan(resp.domain, vorp, ok).then(async() => {
							vorp.log();
							log(vorp,"Scanning for potential high-value target directories...");
							await scanners.domain.potentialTargetScan(resp.domain, vorp, ok).then(() => {
								vorp.log();
								c();
							});
						});
					});
				});
				break;
			default:
				vorp.log(`    ${chalk.yellow(a.type)} is not a valid type.\\n`);
				c();
				break;
		}
	});

vorp
	.catch("[cmds...]", "Catches unknown commands.")
	.action((a,c) => {
		vorp.log(`    ${chalk.yellow(a.cmds.join())} is not a valid command.\\n    Use ${chalk.yellow("help")} for a list of commands.\\n`);
		c();
	});

clear();

console.log(chalk.red("     ____  _____ _____   ________   ")+"_____       _ __");
console.log(chalk.red("    / __ \\/ ___//  _/ | / /_  __/  ")+"/ ___/__  __(_) /____");
console.log(chalk.red("   / / / /\\__ \\ / //  |/ / / /     ")+"\\__ \\/ / / / / __/ _ \\");
console.log(chalk.red("  / /_/ /___/ // // /|  / / /     ")+"___/ / /_/ / / /_/  __/");
console.log(chalk.red("  \\____//____/___/_/ |_/ /_/     ")+"/____/\\__,_/_/\\__/\\___/   v1.0.0\n\n");

vorp.delimiter(chalk.magenta("  Suite>")).show();