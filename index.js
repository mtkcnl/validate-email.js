//#region License
/* 
    validate-email.js Email Validation for Node.js applications
    Copyright (C) 2025  Murat Tokcanli

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
//#endregion License
const dns = require("dns").promises;
const domainBlacklist = require('./domains.json') // Taken from https://github.com/romainsimon/emailvalid/blob/master/domains.json
class Validator {
	#options;
	constructor(options) {
		this.#options = { 
			blacklist: options?.blacklist || domainBlacklist,
			allowFreemail: options?.allowFreemail || false,
			allowDisposable: options?.allowDisposable || false 
		}
	}

	async #validateEmailDns(email) {
		const domain = email.split("@")[1];
		if (!domain) return { valid: false, reason: "invalid_email_format" };

		let mxRecords;
		try {
			mxRecords = await dns.resolveMx(domain);
		} catch (err) {
			return { valid: false, reason: "no_mx" };
		}

		if (!mxRecords.length) {
			return { valid: false, reason: "no_mx" };
		}

		// Priority'e göre sırala
		mxRecords.sort((a, b) => a.priority - b.priority);

		const results = [];

		for (const mx of mxRecords) {
			const exchange = mx.exchange;

			// 1) MX to A records 
			let ips = [];
			try {
				ips = await dns.resolve4(exchange);
			} catch {
				// Try IPv6
				try {
					ips = await dns.resolve6(exchange);
				} catch {
					results.push({
						mx: exchange,
						valid: false,
						reason: "mx_host_unresolvable",
					});
					continue;
				}
			}

			// 2) Check PTR records
			let ptrOk = false;
			for (const ip of ips) {
				try {
					let ptrQuery;

					if (ip.includes(".")) {
						// IPv4 PTR
						ptrQuery = ip.split(".").reverse().join(".") + ".in-addr.arpa";
					} else {
						// IPv6 reverse for PTR
						const full = this.#expandIpv6(ip)
							.join("")
							.split("")
							.reverse()
							.join(".");
						ptrQuery = full + ".ip6.arpa";
					}

					const ptr = await dns.resolvePtr(ptrQuery);

					if (ptr && ptr.length > 0) {
						ptrOk = true;
					}
				} catch { }
			}

			results.push({
				mx: exchange,
				ips,
				ptrOk,
			});
		}

		const anyPtrOk = results.some((x) => x.ptrOk);

		return {
			valid: true, // Domain can recieve mails
			mxRecords: results,
			ptrStatus: anyPtrOk ? "good" : "suspicious",
		};
	}
	// IPv6 expand helper
	#expandIpv6(ip) {
		const parts = ip.split("::");
		let head = parts[0].split(":").filter(Boolean);
		let tail = parts[1] ? parts[1].split(":").filter(Boolean) : [];

		const missing = 8 - (head.length + tail.length);
		const zeros = Array(missing).fill("0");

		return [...head, ...zeros, ...tail].map((x) => x.padStart(4, "0"));
	}

	async validate(email) {
		const domain = email.split('@')[1],
		isBlacklisted = this.#options.blacklist && Object.keys(this.#options.blacklist).includes(domain);
		let dnsResults = {valid:false},
		domainAllowed = true;
		if(this.#options.blacklist)
		{
			const entry = Object.entries(this.#options.blacklist)?.find(([_domain]) => _domain === domain)
			domainAllowed = (!isBlacklisted) || (this.#options.allowDisposable && entry[1] === 'disposable') || (this.#options.allowFreemail && entry[1] === 'freemail');
		}
		if (domainAllowed)
			dnsResults = await this.#validateEmailDns(email);

		return {
			dnsResults,
			domainAllowed
		}
	}

}

module.exports = exports.default = Validator;