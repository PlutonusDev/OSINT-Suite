const { get } = require("snekfetch");
const jssoup = require("jssoup").default;
const crypto = require("crypto");
const wait = require("util").promisify(setTimeout);

module.exports = {
	localityScan: number => {
		return new Promise(async(res, rej) => {
			let secret;
			await get("https://numverify.com/").then(resp => {
				let soup = new jssoup(resp.body);
				for(elem of soup.findAll("input", {"type":"hidden"})) {
					if(elem.attrs.name=="scl_request_secret") secret = elem.attrs.value;
				}
			});
			
			let apikey = crypto.createHash("md5").update((number + secret).toString()).digest("hex");
			get(`https://numverify.com/php_helper_scripts/phone_api.php?secret_key=${apikey}&number=${number}`, {
				headers: {
					["Host"]: "numverify.com",
					["User-Agent"]: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0",
					["Accept"]: "application/json, text/javascript, */*; q=0.01",
					["Accept-Language"]: "en-US;q=0.5",
					["Referer"]: "https://numverify.com/",
					["X-Requested-With"]: "XMLHttpRequest",
					["DNT"]: "1",
					["Connection"]: "keep-alive",
					["Pragma"]: "no-cache",
					["Cache-Control"]: "no-cache"
				}
			}).then(resp => {
				res({data:resp.body,key:apikey,secret:secret});
			}).catch(()=>rej());
		});
	},
	
	footprintScan: number => {
		return new Promise(async (res, rej) => {
			return res([]);
			let results = [];
			google("\""+number+"\"", (e,resp) => {
				if(e)return rej(e);
				console.log(require("util").inspect(resp));
				for(elem of resp.links) {
					results.push(elem.title);
				}
				res(results);
			});
		});
	},
	
	ovhScan: number => {
		return new Promise(async (res, rej) => {
			get("https://api.ovh.com/1.0/telephony/number/detailedZones")
		});
	}
}