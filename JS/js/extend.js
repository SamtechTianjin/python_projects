(function (arg) {
    arg.extend({
        Sam: function() {
            return "Liuming";
        },
        Sugar: function () {
            return "Liushuge";
        },
    });

    arg.fn.extend({
        Jack: function () {
            return "Jack";
        },
        Rose: function () {
            return "Rose";
        }
    });
})(jQuery);