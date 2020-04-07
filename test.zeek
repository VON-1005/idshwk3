type x: set[string];
global a: table[addr] of x;

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
	if (c$id$resp_h !in a)
	{
		a[c$id$resp_h]=add x[c$http$user_agent];
	}
	else if (c$id$resp_h in a)
	{
		if (c$http$user_agent !in a[c$id$resp_h])
		{
			a[c$id$resp_h]=add x[c$http$user_agent];
		}
	}
}

event zeek_done()
{
	for (key in a)
	{
		if (|a[key]| >= 3)
		{
			print fmt("%s is a proxy",key);
		}
	}
}

