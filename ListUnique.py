def unique(list1):
	u = []
	for i in list1:
		if i not in u:
			u.append(i)
	
	return u
