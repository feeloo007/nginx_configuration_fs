{% macro loop_on_redirected_code() -%}
    {% for redirect_code in extra_from_distrib_configurations.redirected_uri_extra.properties.redirect_code.enum -%}
    {{ caller( redirect_code ) }}
    {% endfor -%}
{% endmacro -%}

{% macro default_redirected_code() -%}
    {{ caller( extra_from_distrib_configurations.redirected_uri_extra.properties.redirect_code.default ) }}
{% endmacro -%}
