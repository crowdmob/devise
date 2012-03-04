Warden::Manager.after_set_user :except => :fetch do |record, warden, options|
  scope = options[:scope]
  if record.respond_to?(:dynamo_remember_me) && record.dynamo_remember_me && warden.authenticated?(scope)
    Devise::Controllers::DynamoRememberable::Proxy.new(warden).dynamoremember_me(record)
  end
end