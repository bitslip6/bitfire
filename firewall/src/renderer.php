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
namespace ThreadFin\view;

use function ThreadFin\_t;

use const ThreadFin\DAY;

/**
 * take a unix timestamp and return localized string for number of days ago
 * @param string $epoch 
 * @return string 
 */
function days_format(string $epoch) : string {
	$t = intval($epoch);
	if ($t > 1) {
		$diff = time() - $t;
		$r = floor($diff / DAY);
		if ($r == 0) { return _t("today"); }
		if ($r > 0 && $r < 1024) { return  $r . _t(" days ago"); }
	}
	return _t("never");
}

function checked($value) : string {
	if ($value) { return " checked='checked' "; }
	return "X";
}


/**
 * @param string $text 
 * @return string returns the unmodified $text
 */
function identity(string $text) : string {
	return $text;
}

/**
 * escape user input for display on rendered page
 * @param string $text 
 * @param null|callable $next_fn 
 * @return string 
 */
function escape(string $text) : string {
	return htmlspecialchars($text, ENT_QUOTES, 'UTF-8', false);
}

/**
 * count the number of elements in an array, or 0 for any other input type
 * @param mixed $input 
 * @return string 
 */
function counter($input) : string {
	if (is_array($input)) {
		return count($input);
	}
	return "0";
}



namespace ThreadFin;

use DOMDocument;
use DOMNode;
use DOMXPath;
use ThreadFin\Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;

use function ThreadFin\partial_right as BINDR;
use function ThreadFin\debug;
use function ThreadFin\icontains;
use BitFire\Config as CFG;

const NOT_MINIFY_EXTENSIONS = ["svg", "min"];
const MODIFIER_MAPPING = [
	"-" => "\ThreadFin\\view\\escape",
	"+" => "intval",
	"%d" => "\ThreadFin\\view\\days_format",
	"%u" => "strtoupper",
	"%U" => "ucfirst",
	"%W" => "ucwords",
	"%h" => "\ThreadFin\\view\\checked",
	"%c" => "ThreadFin\\view\\counter"
];
// CHAR FORMAT matches single character modifiers
const CHAR_FORMAT = "[+-]";
const MAX_VAR_REPLACEMENT = 1000;
const DO_MINIFY = true;


/**
 * extract innerHTML from a node
 * @param DOMNode $element 
 * @return string 
 */
function inner_html(DOMNode $element) : string {
    $innerHTML = "";
    $children  = $element->childNodes;

    foreach ($children as $child) {
        $innerHTML .= $element->ownerDocument->saveHTML($child);
    }

    return $innerHTML;
}


/**
 * pure function to minify HTML.
 * This will remove all newlines excess whitespace and comments.
 * @param string $in 
 * @return string 
 */
function minify_str(string $in) : string {
	//$t1 = preg_replace("/[\s\n]+/m", " ", $in);
	//$t2 = preg_replace("/>\s+</", "><", $t1);
	//$t3 = preg_replace("/<!--.*?-->/", "", $t2);
	$t3 = $in;
	if (empty($t3)) { return ""; }

	if (!class_exists("DOMDocument")) {
		return $in;
	}

	libxml_use_internal_errors(false);

	// load XML
	$doc = new DOMDocument();
	if (CFG::enabled("debug_file")) {
		$doc->preserveWhiteSpace = false;
		$doc->formatOutput = true;
	}
	$doc->loadHTML($t3, LIBXML_NOWARNING | LIBXML_NOERROR | LIBXML_NOCDATA | LIBXML_NONET);
	foreach (libxml_get_errors() as $error) {
		debug("libxml: %s:%d [%s]", $error->file, $error->line, $error->message);
	}
	
	// find all content to translate
	libxml_clear_errors();
	$xpath = new DOMXpath($doc);
	$elms = $xpath->query("//*[contains(@class,'tdc')]");
	debug("translating %d tags\n", $elms->count());
	for ($i = 0; $i < $elms->count(); $i++) {
		$in = trim(inner_html($elms->item($i)));
		$translated = _t($in);
		$t3 = str_replace($in, $translated, $t3);
	}

	return $t3;
}

/**
 * add a new string modifier to the list of available view modifiers
 * if $modifier_fn is NULL returns the modifier already mapped to $modifier_name
 * @param null|string $modifier_name 
 * @param null|callable $modifier_fn 
 * @return array 
 */
function view_modifier(string $modifier_name, ?callable $modifier_fn = null) : ?Callable {
	static $mapping = MODIFIER_MAPPING;

	if ($modifier_fn === NULL) {
		$modifiers = explode("|", $modifier_name);

		$idx = 0;
		$fn = $mapping[$modifiers[0]]??NULL;
		while(isset($modifiers[++$idx])) {
			// echo "CHAIN $fn = {$modifiers[$idx]}\n";
			$fn = chain($fn, $mapping[$modifiers[$idx]]??NULL);
		}
		return $fn;
	}

	$mapping[$modifier_name] = $modifier_fn;
	return NULL;
}


/**
 * pure function to minify HTML files.
 * 
 * @param string $filename 
 * @return Effect 
 */
function minify(string $filename) : Effect {
	$effect  = Effect::new();

	$extension = pathinfo($filename, PATHINFO_EXTENSION);
	// just serve minified files directly
	if ($extension === "min") {
		$effect->out(
			FileData::new($filename)->raw()
		);
	}
	// if the file is minify-able
	else if (DO_MINIFY && ! icontains($extension, NOT_MINIFY_EXTENSIONS)) {
		$min_filename = "{$filename}.min";
		$min_file = FileData::new($min_filename);
		// if we have a minified version on disk, serve that

		if ($min_file->exists && filemtime($min_filename) > filemtime($filename)) {
			$effect->out($min_file->raw());
		}
		// read the raw file, minify it and return an effect to write the
		// minified file to disk
		else {
			//echo "<h1>$filename</h1>\n";
			$source_content = FileData::new($filename)->raw();
			$min_content = minify_str($source_content);
			$effect->out($min_content);
			$effect->file(new FileMod($min_filename, $min_content, \BitFire\FILE_RW));
		}
	}

	return $effect;
}


/**
 * pure function to render the file source with any replacements, src_root unused
 */
function render_file(string $src2, array $replacements = array()) : string {
	$min_effect = minify($src2);
	$content = $min_effect->read_out(true);
	$min_effect->run();
	$rendered = process_line($content, $replacements);
	return $rendered;
}



/**
 * the view variable replacement code.  
 * supports string, array and object access with the dot operator
 * @param array $x 
 * @param array $replacements 
 * @return string 
 */
function content_replacement(array $x, array $replacements) {
	$mod_fn = NULL;
	if (!empty($x[2])) {
		$mod_fn = view_modifier($x[2]);
	}
	$primary = $x[3];
	$secondary = $x[4]??"";

	// replace content.  apply any view modifiers
	if (isset($replacements[$primary])) {
		$return = $replacements[$primary];
		if (!empty($secondary)) {
			if (is_object($return)) {
				if (isset($return->$secondary)) {
					$value = $return->$secondary;
				}
			}
			else if (is_array($return)) {
				if (isset($return[$secondary])) {
					$value = $return[$secondary];
				}
			}
			else {
				$value = (string)$return;	
			}
		}
		else {
			$value = (string)$return;	
		}
		if (!isset($value)) {
			debug("VIEW VAR MISSING %s.%s", $primary, $secondary);
			$value = "";
		}
		return ($mod_fn == NULL) ? $value : $mod_fn($value);
	}

	debug("unset view variable [%s.%s]", $primary, $secondary);
	return "undefined [{$primary}.{$secondary}]";
}

function template_replacement_min(string $template_markup, string $template_var, string $var_name, array $replacements) : string {
	$content = "";
	foreach($replacements[$var_name] as $item) {
		$replacements[$template_var] = $item;
		$content .= process_line($template_markup, $replacements);
	}
	return $content;
}

/**
 * 
 */
function template_replacement(array $x, array $replacements, array $templates) {
	$template_name = $x[1];
	$var_name = $x[2];
	$content = "";
	$template_arr = $templates[$template_name]??[];
	$template_var = $template_arr[0]??$var_name;
	$template_markup = $template_arr[1]??"";
	if (isset($replacements[$var_name]) && is_array($replacements[$var_name]) && count($replacements[$var_name]) > 0) {
		foreach($replacements[$var_name] as $item) {
			$replacements[$template_var] = $item;
			$content .= process_line($template_markup, $replacements);
		}
	}
	return $content;
}


/**
 * replace all variables in a line with data from replacements, sub render any included content
 * and templates
 */
function process_line(string $line, array $replacements) : string {
	// internal templates
	$templates = [];

	//extract inline templates
	$line = preg_replace_callback(
		"/{{\s*template\s*:\s*(\w+)[\s\:]+[\'\"]?(\w+)[\'\"]?\s*}}\s*(.*?){{\s*end[\s\:]+template\s*}}/mis",
		function($x) use (&$templates) {
			$templates[$x[1]] = [$x[2], $x[3]];
			return "";
	}, $line);

	// replace variable substitution
	$line = preg_replace_callback("/{{\s*((\%[a-zA-Z]|".CHAR_FORMAT."|\|)*)*\s*([_\w-]+)\.?([_\w-]*)\s*}}/", 
	BINDR("ThreadFin\\content_replacement", $replacements), $line, MAX_VAR_REPLACEMENT);

	// replace inline templates
	$line = preg_replace_callback("/{{\s*render[\s:]+(\w+)\s+[\'\"]?(\w+)[\'\"]?\s*}}/",
	BINDR("ThreadFin\\template_replacement", $replacements, $templates), $line, MAX_VAR_REPLACEMENT);

	// include sub templates, params will be injected into view variables
	// {{> path/to/view param1="value" param2="value" }}
	$line = preg_replace_callback("/{{>\s*([^\s}]+)\s*([^}]*)}}/", 
		function ($x) use ($replacements) {
			preg_match_all("/([_\w]+)\s*=\s*\"([^\"]*)/", $x[2], $matches);
			$params = array();
			for ($i=0,$m=count($matches[1]);$i<$m;$i++) {
				$params[$matches[1][$i]] = $matches[2][$i];
			}

			$replacements = array_merge($replacements, $params);
			return render_file(VIEW_ROOT . DS . $x[1], $replacements);
		 }, $line, MAX_VAR_REPLACEMENT);

	return $line;
}

