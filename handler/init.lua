function apply_default_config()
	if iocaine.config.minify == nil then
		iocaine.config.minify = true
	end

	if iocaine.config["trusted-user-agents"] == nil then
		iocaine.config["trusted-user-agents"] = { "indieauth" }
	end

	if iocaine.config["trusted-paths"] == nil then
		iocaine.config["trusted-paths"] = { "/robots.txt" }
	end

	if iocaine.config.firewall == nil then
		iocaine.config.firewall = {}
	end
	if iocaine.config.firewall["block-rule-hits"] == nil then
		iocaine.config.firewall["block-rule-hits"] = { "poisoned-url" }
	end

	if iocaine.config.garbage == nil then
		iocaine.config.garbage = {}
	end

	if iocaine.config["unwanted-asns"] == nil then
		iocaine.config["unwanted-asns"] = {}
	end

	local asn_list = iocaine.config["unwanted-asns"].list
	if asn_list == nil or
		(type(asn_list) == "table" and #asn_list == 0) then
		iocaine.log.info("using default unwanted asns")
		iocaine.config["unwanted-asns"].list = {
			37963,  -- Alibaba
			45102,  -- Alibaba
			134963, -- Alibaba
			34947,  -- Alibaba
			55990,  -- Huawei
			136907, -- Huawei
			63655,  -- Huawei
			141180, -- Huawei
			265443, -- Huawei
			149640, -- Huawei
			200756, -- Huawei
			206798, -- Huawei
			151610, -- Huawei
			206204, -- Huawei
			131444  -- Huawei
		}
	end

	if iocaine.config.garbage["status-code"] == nil then
		iocaine.config.garbage["status-code"] = 200
	end
	if iocaine.config.garbage["fallthrough-status-code"] == nil then
		iocaine.config.garbage["fallthrough-status-code"] = 421
	end
	if iocaine.config.garbage.title == nil then
		iocaine.config.garbage.title = {}
	end
	if iocaine.config.garbage.title["min-words"] == nil then
		iocaine.config.garbage.title["min-words"] = 2
	end
	if iocaine.config.garbage.title["max-words"] == nil then
		iocaine.config.garbage.title["max-words"] = 15
	end

	if iocaine.config.garbage.paragraphs == nil then
		iocaine.config.garbage.paragraphs = {}
	end
	if iocaine.config.garbage.paragraphs["min-count"] == nil then
		iocaine.config.garbage.paragraphs["min-count"] = 1
	end
	if iocaine.config.garbage.paragraphs["max-count"] == nil then
		iocaine.config.garbage.paragraphs["max-count"] = 5
	end
	if iocaine.config.garbage.paragraphs["min-words"] == nil then
		iocaine.config.garbage.paragraphs["min-words"] = 10
	end
	if iocaine.config.garbage.paragraphs["max-words"] == nil then
		iocaine.config.garbage.paragraphs["max-words"] = 69
	end

	if iocaine.config.garbage.links == nil then
		iocaine.config.garbage.links = {}
	end
	if iocaine.config.garbage.links["min-count"] == nil then
		iocaine.config.garbage.links["min-count"] = 1
	end
	if iocaine.config.garbage.links["max-count"] == nil then
		iocaine.config.garbage.links["max-count"] = 8
	end
	if iocaine.config.garbage.links["min-uri-parts"] == nil then
		iocaine.config.garbage.links["min-uri-parts"] = 1
	end
	if iocaine.config.garbage.links["max-uri-parts"] == nil then
		iocaine.config.garbage.links["max-uri-parts"] = 2
	end
	if iocaine.config.garbage.links["min-text-words"] == nil then
		iocaine.config.garbage.links["min-text-words"] = 2
	end
	if iocaine.config.garbage.links["max-text-words"] == nil then
		iocaine.config.garbage.links["max-text-words"] = 5
	end
	if iocaine.config.garbage.links["uri-separator"] == nil then
		iocaine.config.garbage.links["uri-separator"] = "-"
	end
end

function init_metrics()
	iocaine.log.debug("Registering metrics")
	local qmk_requests = iocaine.metrics.registry:new_counter(
		"qmk_requests", "Number of requests received", "host"
	)
	iocaine.metrics.loaded:update(qmk_requests)

	local qmk_ruleset_hits = iocaine.metrics.registry:new_counter(
		"qmk_ruleset_hits", "Number of times a ruleset has been hit",
		"ruleset", "outcome"
	)
	iocaine.metrics.loaded:update(qmk_ruleset_hits)

	local qmk_garbage_generated = iocaine.metrics.registry:new_counter(
		"qmk_garbage_generated", "Amount of garbage generated, in bytes",
		"host"
	)
	iocaine.metrics.loaded:update(qmk_garbage_generated)

	_G.METRIC_REQUESTS = qmk_requests
	_G.METRIC_RULESET_HITS = qmk_ruleset_hits
	_G.METRIC_GARBAGE_GENERATED = qmk_garbage_generated
end

function init_check_ai_robots_txt()
	local path = iocaine.config["ai-robots-txt-path"]
	local data = {}
	if not path then
		iocaine.log.warn("No ai-robots-txt-path configured, using default")
		data = iocaine.serde.parse_json(iocaine.file.read_embedded("/defaults/etc/robots.json"))
	else
		iocaine.log.debug(string.format("Loading ai-robots-txt from %s", path))
		data = iocaine.file.read_as_json(path)
	end

	local keys = {}
	for k, _ in pairs(data) do
		table.insert(keys, k)
	end

	_G.AI_ROBOTS_TXT = iocaine.matcher.Patterns(table.unpack(keys))
end

function init_check_major_browsers()
	_G.MAJOR_BROWSERS = iocaine.matcher.Patterns("Chrome/", "Firefox")
end

function init_check_unwanted_visitors()
	local unwanted = iocaine.config["unwanted-visitors"]
	if unwanted == nil then
		unwanted = {"Perplexity", }
	end
	_G.UNWANTED_VISITORS = iocaine.matcher.Patterns(table.unpack(unwanted))
end

function init_sources()
	local sources = iocaine.config.sources
	if not sources then
		_G.MARKOV = iocaine.generator.Markov()
		_G.WORDLIST = iocaine.generator.WordList()
		return
	end

	local corpus_sources = sources["training-corpus"]
	if corpus_sources then
		if type(corpus_sources) == "table" then
			_G.MARKOV = iocaine.generator.Markov(table.unpack(corpus_sources))
		else
			_G.MARKOV = iocaine.generator.Markov(corpus_sources)
		end
	else
		_G.MARKOV = iocaine.generator.Markov()
	end

	local wordlists = sources.wordlists
	if wordlists then
		if type(wordlists) == "table" then
			_G.WORDLIST = iocaine.generator.WordList(table.unpack(wordlists))
		else
			_G.WORDLIST = iocaine.generator.WordList(wordlists)
		end
	else
		_G.WORDLIST = iocaine.generator.WordList()
	end
end

function init_template()
	local template
	if iocaine.config.template then
		iocaine.log.debug("HTML template loaded from configuration")
		template = iocaine.config.template
	elseif iocaine.config["template-file"] then
		iocaine.log.debug(string.format("Loading HTML template from %s", iocaine.config["template-file"]))
		template = iocaine.file.read_as_string(iocaine.config["template-file"])
	else
		iocaine.log.debug("Loading embedded HTML template")
		template = iocaine.file.read_embedded("/defaults/templates/garbage.html")
	end

	iocaine.log.debug("Initializing template engine")
	_G.ENGINE = iocaine.TemplateEngine()
	_G.TEMPLATE_HTML = ENGINE:compile(template)
end

function init_logging()
	local logging_enabled = false
	if iocaine.config["logging"] then
		logging_enabled = true;
	end
	_G.LOGGING_ENABLED = logging_enabled
end

function init_asn()
	local db_path = iocaine.config["unwanted-asns"]["db-path"]
	if db_path == nil then
		iocaine.log.warn("No unwanted-asns.db-path configured, check disabled");
		_G.ASN = iocaine.matcher.Never()
	else
		local list = iocaine.config["unwanted-asns"].list
		if type(list) ~= "table" then
			list = { list }
		end
		for i = 1, #list do
			list[i] = tonumber(list[i])
		end
		_G.ASN = iocaine.matcher.ASN(db_path, table.unpack(list))
	end
end

function init_trusted_user_agents()
	local trusted = iocaine.config["trusted-user-agents"]
	if trusted == nil then
		_G.TRUSTED_AGENTS = iocaine.matcher.Never()
	else
		if type(trusted) ~= "table" then
			trusted = { trusted }
		end
		_G.TRUSTED_AGENTS = iocaine.matcher.Patterns(table.unpack(trusted))
	end
end

function init_trusted_ips()
	local trusted = iocaine.config["trusted-ips"]
	if trusted == nil then
		_G.TRUSTED_IPS = iocaine.matcher.Never()
	else
		if type(trusted) ~= "table" then
			trusted = { trusted }
		end
		_G.TRUSTED_IPS = iocaine.matcher.IPPrefixes(table.unpack(trusted))
	end
end

function init_trusted_paths()
	local trusted = iocaine.config["trusted-paths"]
	if trusted == nil then
		_G.TRUSTED_PATHS = iocaine.matcher.Never()
	else
		if type(trusted) ~= "table" then
			trusted = { trusted }
		end
		_G.TRUSTED_PATHS = iocaine.matcher.Patterns(table.unpack(trusted))
	end
end

function init_poison_id()
	local poison_ids = iocaine.config["poison-id"]
	local poison_ids_len = 0
	if poison_ids == nil then
		poison_ids_len = 1
		poison_ids = { iocaine.instance_id }
	else
		if type(poison_ids) ~= "table" then
			poison_ids_len = 1
			poison_ids = { poison_ids }
		else
			for k, v in ipairs(poison_ids) do
				poison_ids_len = poison_ids_len + 1
				if v == "+" then
					poison_ids[k] = iocaine.instance_id
				end
			end
		end
	end

	iocaine.log.info("poison-ids: " .. table.concat(poison_ids, ", "))
	_G.POISON_IDS = poison_ids
	_G.POISON_IDS_LEN = poison_ids_len
	_G.POISON_ID_PATTERNS = iocaine.matcher.Patterns(table.unpack(poison_ids))
end

function init_firewall()
	iocaine.log.debug("Setting up base firewall rules")

	local block_rule_hits = iocaine.config["firewall"]["block-rule-hits"]
	if type(block_rule_hits) ~= "table" then
		block_rule_hits = { block_rule_hits }
	end

	_G.FIREWALL_BLOCK_RULE_HITS = iocaine.matcher.Patterns(table.unpack(block_rule_hits))
end

function init()
	apply_default_config()
	init_metrics()
	init_trusted_user_agents()
	init_trusted_paths()
	init_trusted_ips()
	init_check_ai_robots_txt()
	init_check_major_browsers()
	init_check_unwanted_visitors()
	init_firewall()
	init_asn()
	init_sources()

	init_template()
	init_logging()
	init_poison_id()
end

return init

