#!/usr/bin/env python3

#	dsmap - DNS Security Mapper
#
#	Copyright ©2014  Simon Arlott
#
#	This program is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import collections
import dns.flags
import dns.resolver
import sys
from tabulate import tabulate
import yaml

res = dns.resolver.Resolver()
res.set_flags(dns.flags.from_text("AD RD"))


def main(args):
	parser = argparse.ArgumentParser(prog=args[0], description="DNS Security Mapper")
	parser.add_argument("-i", "--input-file", action="append", metavar="FILE", help="Load config from FILE")
	args = parser.parse_args(args[1:])
	config = {}

	if args.input_file:
		for filename in args.input_file:
			with open(filename, "r", encoding="UTF-8") as f:
				update(config, yaml.safe_load(f))

	if not config:
		parser.print_usage()
		return 255

	config["domains"].sort(key=lambda x: x["name"] if "name" in x else x["domain"] if "domain" in x else "")
	data = run(config)
	ptable(data)


def update(dict, other):
	for key, value in other.items():
		if isinstance(value, collections.Mapping):
			dict[key] = update(dict.get(key, {}), value)
		elif isinstance(dict.get(key), collections.Sequence):
			if isinstance(value, collections.Sequence):
				dict[key].extend(value)
			else:
				dict[key].append(value)
		elif isinstance(value, collections.Sequence):
			dict[key] = [dict[key]] if key in dict else []
			dict[key].extend(value)
		elif isinstance(dict, collections.Mapping):
			dict[key] = value
		else:
			dict = { key: value }
	return dict


def query(*args):
	try:
		ans = res.query(*args)
		if bool(ans.response.flags & dns.flags.from_text("AD")):
			return ans
		return False
	except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.YXDOMAIN):
		return None


def has_ds(domain):
	return bool(query(domain, "DS"))

def has_tlsa(hostname, proto="tcp", port=443):
	return bool(query("_{1:d}._{0:s}.{2:s}".format(proto, port, hostname), "TLSA"))

def has_dmarc(domain):
	ans = query("_dmarc.{0:s}".format(domain), "TXT")
	if ans:
		for rr in ans:
			rr = dict((x[0], x[2]) for x in (entry.partition("=") for entry in "".join(rr.strings).replace(" ", "").split(";")))
			if rr.get("v") == "DMARC1":
				if rr.get("p") == "reject":
					return "R"
				elif rr.get("p") == "quarantine":
					return "Q"
				elif rr.get("p") == "none":
					return "N"
	return None


def run(config):
	data = []

	for domain in config["domains"]:
		if "domain" in domain:
			record = domain.copy()
			if "name" not in record:
				record["name"] = record["domain"]
			record["DS"] = has_ds(domain["domain"])
			record["TLSA"] = has_tlsa(domain["hostname"]) if "hostname" in domain else None
			record["DMARC"] = has_dmarc(domain["domain"])
			data.append(record)

	return data


def ptable(data):
	data = [["{name} <{domain}>".format(**x), "*" if x["DS"] else "", "*" if x["TLSA"] else "", x["DMARC"]] for x in data]
	print(tabulate(data, headers=["Name", "DS", "TLSA", "DMARC"], tablefmt="grid"))


if __name__ == "__main__":
	sys.exit(main(sys.argv))
