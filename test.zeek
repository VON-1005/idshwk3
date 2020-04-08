global first_u: table[addr] of string = {};     #存ip的第一个user_agent
global second_u: table[addr] of string = {};    #存ip的第二个不同的user_agent
global counter_u: table[addr] of int = {};        #存与ip关联的user_agent数

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	local users: string = to_lower(c$http$user_agent);       #大小写
	if (c$id$resp_h in first_u){
		if (users == first_u[c$id$resp_h]){}
		else{     #第二个不同的user_agent
			if (c$id$resp_h in second_u){
				if (users == second_u[c$id$resp_h]){}
				else{    #多于两个不同的user_agent
					counter_u[c$id$resp_h] += 1;
				}
			}
			else{    #c$id$resp_h !in second_u
				second_u[c$id$resp_h] = users;
				counter_u[c$id$resp_h] += 1;
			}    #两个不同的user_agent
		}
	}
	else{    #c$id$resp_h !in first_u
		first_u[c$id$resp_h] = users;
		counter_u[c$id$resp_h] = 1;
	}    #一个user_agent
}

event zeek_done()
{
	for (key, val in counter_u){
		if (val >= 3){
			print fmt("%s is a proxy", key);
		}
	}
}


