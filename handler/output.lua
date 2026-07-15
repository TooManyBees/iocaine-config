function output(request, decision)
	local decision = decision or "default"

	local response = iocaine.Response()
	if decision == "default" then
		response.status = iocaine.config.garbage["fallthrough-status-code"]
	else
		make_garbage_response(request, response)
		METRIC_GARBAGE_GENERATED:inc_by(response.content_length, request:header("host"))
	end

	return response
end

function make_garbage_response(request, response)
	local context = generate_garbage(request)

	response.status = iocaine.config.garbage["status-code"]
	response:set_header("content-type", "text/html")
	response.body = ENGINE:render(TEMPLATE_HTML, context)
	if iocaine.config.minify then
		response:minify()
	end
end

function generate_garbage(request)
	local cfg = iocaine.config
	local rng = iocaine.generator.Rng:from_request(request, "default")
	local html_escape = iocaine.html_escape
	local urlencode = iocaine.urlencode

	local paragraphs = {}
	local paragraph_count = rng:in_range(
		cfg.garbage.paragraphs["min-count"],
		cfg.garbage.paragraphs["max-count"]
	)
	for i = 1, paragraph_count do
		paragraphs[i] = html_escape(
			MARKOV:generate(
				rng,
				rng:in_range(
					cfg.garbage.paragraphs["min-words"],
					cfg.garbage.paragraphs["max-words"]
				)
			)
		)
	end

	local links = {}
	local link_count = rng:in_range(
		cfg.garbage.links["min-count"],
		cfg.garbage.links["max-count"]
	)
	for i = 1, link_count do
		links[i] = {
			path = urlencode(
				WORDLIST:generate(
					rng,
					rng:in_range(
						cfg.garbage.links["min-uri-parts"],
						cfg.garbage.links["max-uri-parts"]
					),
					cfg.garbage.links["uri-separator"]
				)
			),
			text = html_escape(
				MARKOV:generate(
					rng,
					rng:in_range(
						cfg.garbage.links["min-text-words"],
						cfg.garbage.links["max-text-words"]
					)
				)
			)
		}
	end

	local poison_id
	-- if POISON_ID_PATTERNS:matches(request.path) then
	-- 	poison_id = ""
	-- else
		local idx = rng:in_range(1, POISON_IDS_LEN)
		poison_id = urlencode(POISON_IDS[idx]) .. cfg.garbage.links["uri-separator"]
	-- end

	return {
		title = MARKOV:generate(
			rng,
			rng:in_range(
				cfg.garbage.title["min-words"],
				cfg.garbage.title["max-words"]
			)
		),
		random_year = rng:in_range(1963, 2016),
		random_author = html_escape(MARKOV:generate(rng, rng:in_range(1, 4))),
		request = {
			host = request:header("host"),
			uri = request.path,
		},
		garbage = {
			paragraphs = paragraphs,
			links = links,
		},
		poison_id = poison_id,
	}
end

return output

