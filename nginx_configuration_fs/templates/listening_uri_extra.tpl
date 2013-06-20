{% macro is_case_sensitive( extra ) -%}
{% if extra.case == 'U' -%}~*{% elif extra.case == 'S' -%}~{% endif -%}
{%- endmacro %}
