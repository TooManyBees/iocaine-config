function decide(request)
	-- local trusted_decision_header = iocaine.config["trusted-decision-header"]
	-- if trusted_decision_header ~= nil then
	--	local decision = request:header(trusted_decision_header)
	--	if decision ~= nil then
	--		return decision
	--	end
	-- end

	local user_agent = request:header("user-agent")
	local host = request:header("host")

	METRIC_REQUESTS:inc(host)

	if TRUSTED_AGENTS:matches(user_agent) then
		return augment_decision(request, "default", "trusted-agent")
	end

	if TRUSTED_PATHS:matches(request.path) then
		return augment_decision(request, "default", "trusted-path")
	end

	if TRUSTED_IPS:matches(request:header("x-forwarded-for")) then
		return augment_decision(request, "default", "trusted-ip")
	end

	if POISON_ID_PATTERNS:matches(request.path) then
		return augment_decision(request, "garbage", "poisoned-url")
	end

	if ASN:matches(request:header("x-forwarded-for")) then
		return augment_decision(request, "garbage", "asn")
	end

	if AI_ROBOTS_TXT:matches(user_agent) then
		return augment_decision(request, "garbage", "ai.robots.txt")
	end

	if MAJOR_BROWSERS:matches(user_agent) and request:header("sec-fetch-mode") == nil then
		return augment_decision(request, "garbage", "major-browsers")
	end

	if UNWANTED_VISITORS:matches(user_agent) then
		return augment_decision(request, "garbage", "unwanted-visitors")
	end

	return augment_decision(request, "default", "default")
end

function augment_decision(request, decision, ruleset)
	METRIC_RULESET_HITS:inc(ruleset, decision)

	local xff = request:header("x-forwarded-for")
	if xff ~= nil and FIREWALL_BLOCK_RULE_HITS:matches(ruleset) then
		iocaine.firewall.block(xff)
	end

	if LOGGING_ENABLED then
		local log = {
			["_msg"] = "handling request",
			["service"] = "qmk",
			["decision"] = decision,
			["ruleset"] = ruleset,
			["header"] = request:headers(),
			["query"] = request:queries()
		}
		iocaine.log.stdout(log)
	end
	return decision
end

return decide

