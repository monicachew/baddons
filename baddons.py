#!/usr/bin/python
# Given a list of addon ids, return a verdict of bad or not for each id.
# Usage: baddons.py <input_file> <output_file>

import csv
import json
import pycurl
import re
import sys

import StringIO

class BadAddons:
  """A class to detect whether or not a list of addons is bad."""

  def __init__(self, apikey):
    self.APIKEY = apikey
    self.BADDONS = re.compile("crash|uninstall|error|remove|stealth",
                              re.IGNORECASE)
    self.RELEVANT = re.compile("Firefox|extension|addon|Mozilla",
                               re.IGNORECASE)

  def is_bad(self, addon_id):
    """Returns 1 if the addon_id is probably bad, 0 otherwise."""
    # Restrict to results containing firefox to reduce false positives.
    query = "%s+firefox" % addon_id
    # A custom search URL. cx is a global search engine.
    search_url = ("https://www.googleapis.com/customsearch/v1?" +
            "cx=018149516584340204128:67tqllu_gne&key=%s&q=%s&alt=json" %
            (self.APIKEY, query))
    buf = StringIO.StringIO()
    c = pycurl.Curl()
    c.setopt(c.URL, search_url)
    c.setopt(c.WRITEFUNCTION, buf.write)
    c.perform()
    c.close()
    return self.parse_results(buf.getvalue())

  def parse_results(self, result_string):
    """Parses JSON search results and returns 1 if it's probably malware."""
    result = json.loads(result_string)
    if "items" not in result:
      raise Exception("Didn't get meaningful results")
    is_relevant = False
    num_bad = 0
    for i in result["items"]:
      if i["kind"] != "customsearch#result":
        raise Exception("Error in results")
      if self.BADDONS.search(i["title"]) or self.BADDONS.search(i["snippet"]):
        num_bad += 1
      if self.RELEVANT.search(i["title"]) or self.RELEVANT.search(i["snippet"]):
        is_relevant = True
    if is_relevant and num_bad > 3:
      return [ num_bad, 1 ]
    return [ num_bad, 0 ]

  def process_addons(self, input_file, output_file):
    """Reads addon_id and counts, writes output_file with verdict."""
    f_out = open(output_file, "w")
    f_out.write("addon_id,count,num_bad,verdict\n")
    # Each line of the input contains an addon id
    try:
      f_in = open(input_file)
    except IOError as e:
      sys.exit("Can't find file: %s" % e)
    # Kris uses tsv
    tsv_in = csv.reader(f_in, delimiter='\t')
    for l in tsv_in:
      # Strip curly braces from addon_id, if they exist
      addon_id = l[0].translate(None, "{}")
      addon_count = l[1]
      result = self.is_bad(addon_id)
      f_out.write("%s,%s,%s,%s\n" % (addon_id, addon_count, result[0],
                                     result[1]))

    f_in.close()
    f_out.close()


def main():
  if len(sys.argv) < 3:
    sys.exit("Usage: baddons.py <input_file.tsv> <output_file.csv>")
  try:
    f_api = open(".apikey", "r")
  except IOError as e:
    sys.exit("Can't find file: %s" % e)
  apikey = f_api.readline().strip()
  baddons = BadAddons(apikey)
  baddons.process_addons(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
  main()
