#!/usr/bin/env python

import json
import urllib2

# function to read JSON data from specified URL
# and output relevant fields in CSV format
def printList(myUrl):
	jsonData = json.load(urllib2.urlopen(myUrl))
	print "AppName,AppAuthor,AppLink"
	for anEntry in jsonData ['feed'] ['entry']:
		appname = anEntry ['im:name'] ['label']
		appauthor = anEntry ['im:artist'] ['label']
		applink = anEntry ['link'] ['attributes'] ['href'].partition( '?' ) [0]
		print '"%s","%s","%s"' % ( appname, appauthor, applink )

# choosing App Store country and number of results
storeCountry = "us"
numApps = 50
urlFree = "http://itunes.apple.com/%s/rss/topfreeapplications/limit=%d/json" % ( storeCountry, numApps )
urlPaid = "http://itunes.apple.com/%s/rss/toppaidapplications/limit=%s/json" % ( storeCountry, numApps )

# call the function for both free and paid charts
printList ( urlFree )
printList ( urlPaid )
