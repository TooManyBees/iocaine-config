require("init")()

original_decide = require("decide")
original_output = require("output")

function is_auth_request(request)
	return request:header("X-Iocaine-Victim") == nil	
end

function request_with_path(request)
	local path_from_header = request:header("X-Original-Path")
	if path_from_header ~= nil then
		local new_request = iocaine.Request(request.method, path_from_header)
		new_request:set_headers_from(request:headers())	
		return new_request:share()
	else
		return request
	end
end

function decide(request)
	if is_auth_request(request) then
		return original_decide(request_with_path(request))
	else
		return "garbage"
	end
end

function output(request, decision)
	if is_auth_request(request) then
		local response = iocaine.Response()
		if decision ~= "default" then
			response:set_header("X-Iocaine-Victim", tostring(1))
			response.status = 401
		else
			response.status = 200
		end
		return response
	else
		return original_output(request_with_path(request), decision)
	end
end

return {
	decide = decide,
	output = output,
}
