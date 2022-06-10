<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * HTML/JS Recursive Renderer and minifier.
 * TODO: Refactor to use FileData and Effect abstractions.
 */

namespace BitFire;

use function ThreadFin\ends_with;
use function ThreadFin\file_recurse;
use function ThreadFin\trace;
use function ThreadFin\debug;

const MAX_VAR_REPLACEMENT = 100;
const MISSING_VALUE = '';
const SRC_ROOT = "src";
const DOMINIFY = false;

function minify_str(string $in) : string {
	$t1 = preg_replace("/[\s\n]+/m", " ", $in);
	$t2 = preg_replace("/>\s+</", "><", $t1);
	$t3 = preg_replace("/<!--.*?-->/", "", $t2);
	return $t3;
}

//TODO: return the minified version here!
function minify(string $filename) : string {
	if (ends_with($filename, ".min")) { $filename = str_replace(".min", "", $filename); } // don't double minify svg...
	$min = "";
	$minfile = $filename;

	if (!ends_with($filename, "svg") && !ends_with($filename, "min") && DOMINIFY) { 
		debug("x-minify [%s]", $filename);
		$minfile = "{$filename}.min";
		
		if (!file_exists($minfile) || filemtime($filename) > filemtime($minfile)) {
			$in = file_get_contents($filename);
			$min = minify_str($in);
			file_put_contents($minfile, $min, LOCK_EX);
		}
	}
	if (empty($min)) {
		$min = file_get_contents($minfile);
	}

	return $min;
}

// locate sub views...
function make_finder(string $search_file, bool $ext_pos) : callable {
	if ($ext_pos !== false) {
		return function ($x) use ($search_file) : ?string {
			if (is_file($x) && ends_with($x, $search_file)) { return $x; }
			return NULL;
		};
	}

	return function ($x) use ($search_file): ?string {
		if (!is_file($x)) { return NULL;}
		$ext_pos = strrpos($x, ".");

		if ($ext_pos > 1) {
			$x2 = substr($x, 0, $ext_pos);
			if (ends_with($x2, $search_file)) {
				return $x;
			}
		}
		else if (ends_with($x, $search_file)) { return $x; }
		return NULL;
	};
};

// map input name to source file
function find_source(string $src, string $src_root, bool $prefer_amp) : ?string {
	// does the 
	$file = file_get_contents("file_cache.json");

	$cache = json_decode($file, true);
	if (!isset($cache[$src])) {
		$finder = make_finder($src, (bool)strrpos($src, "."));
		$found = file_recurse($src_root, $finder, NULL, array(), true);
		if (!isset($found[0])) { die ("unable to find [$src] in [$src_root]\n"); }
		$tmp = $found[0]??'NANA';
		$cache[$src] = $tmp;
		file_put_contents("file_cache.json", json_encode($cache));
	}
	
	$file = $cache[$src];
	$parts = explode(".", $file);
	$ampfile = $parts[0].".amp";

	$file = ($prefer_amp && file_exists($ampfile)) ? $ampfile : $cache[$src];
	minify($file);
	return "{$file}.min";
}

function render_static(string $src, array $replacements = array(), $src_root = SRC_ROOT) : string {
	$src2 = find_source($src, $src_root, $replacements['isamp']);
	if (empty($src2)) { die ("src [$src] -> [$src2] [$src_root]"); }
	if (is_dir($src2)) { die ("is dir ($src2)\n"); }

	$src2 = str_replace("EN", $replacements['lang'], $src2);
	return process_line(minify($src2), $replacements);
}

/**
 * render the file source with any replacements, src_root unused
 */
function render_file(string $src2, array $replacements = array()) : string {
	return process_line(minify($src2), $replacements);
}

/**
 * return array of key/value pairs from passed string a=b x=y 
 */
function parse_vars(string $in) : array {
	$vars = explode(" ", $in);
	return array_reduce($vars, function ($carry, $x) {
		// split key/value on euqals
		$pos = strpos($x, "=");
		$key = substr($x, 0, $pos);
		$value = substr($x, $pos+1);
		// trim any quotes on value
		$carry[$key] = trim($value, '"\'');
		return $carry;
	}, []);
}

/**
 * replace all variables in line with data from repleacements, sub render any included content
 */
function process_line(string $line, array $replacements) : string {
	$line = preg_replace_callback("/{{(\w+)}}/", function($x) use ($replacements) { return $replacements[$x[1]]??MISSING_VALUE; }, $line, MAX_VAR_REPLACEMENT);
	$line = preg_replace_callback("/{{>\s*([^\s}]+)\s*([^}]*)}}/", 
		function ($x) use ($replacements) {
			preg_match_all("/(\w+)\s*=\s*\"([^\"]*)/", $x[2], $matches);
			$params = array();
			for ($i=0,$m=count($matches[1]);$i<$m;$i++) {
				$params[$matches[1][$i]] = $matches[2][$i];
			}

			$replacements = array_merge($replacements, $params);
			return render_static($x[1], $replacements);
		 }, $line, MAX_VAR_REPLACEMENT);

	return $line;
}
