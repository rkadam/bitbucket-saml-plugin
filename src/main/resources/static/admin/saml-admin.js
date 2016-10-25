(function ($) {

    'use strict';

    var config_resource = AJS.contextPath() + "/rest/samladmin/1.0/config";

    $(document).ready(function() {
        
        $('input[name="save"]').click(function(e) {
        
            var $form = $(this).closest('form');
            $(".post",$form).html("Saving...");

            $.ajax({
                url: config_resource,
                dataType: "json",
                type: "POST",
                contentType: "application/json",
                data: '{ "enforceSSO": "' + AJS.$("#enforceSSO").prop("checked") + '"}',
                processData: false,
                error: function(xhr, data, error) {
                    $(".error."+xhr.responseJSON.field,$form).html(xhr.responseJSON.error);
                    if (xhr.responseJSON.field) {
                        $(".post",$form).html("There were errors, form not saved!");
                    } else {
                        $(".post",$form).html(xhr.responseText);
                    }
                },
                success: function(data, text, xhr) {
                    $(".post",$form).html('');
                    populateForm();
                }
            });
        });

        function populateForm() {
            AJS.$.ajax({
                url: config_resource,
                type: "GET",
                dataType: "json",
                success: function(config) {
                    AJS.$("#enforceSSO").prop("checked", config.enforceSSO === "true");
                }
            });
        }

        populateForm();

    });
})(AJS.$ || jQuery);