<?php
namespace BitFireWordpres;

use FunctionalWP\Effect;

function index() : \FunctionalWP\Effect {
    $effect = Effect::new()->admin_nav(new \FunctionalWP\MenuItem("BitFire Dashboard", "BitFire", "\BitFireWordpress\show_dashboard", "https://bitfire.co/icon.png"));
    return $effect;
}

function show_dashboard() : void {
    \FunctionalWP\EffectRunner(make_dashboard_effect());
}

function make_dashboard_effect() : \FunctionalWP\Effect {
    return Effect::new()->out("BitFire Wordpress Page Out");
}

\FunctionalWP\EffectRunner(index());